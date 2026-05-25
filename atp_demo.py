"""Local ATP v0.3 L1/L2 demo between two localhost agents."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import uvicorn
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from fastapi import FastAPI, HTTPException, Request


ATP_VERSION = "0.3"
TRANSACTION_ID = "atp_photo_001"
RUN_DIR = Path("runs") / TRANSACTION_ID
ARTIFACTS_DIR = RUN_DIR / "artifacts"
GENESIS_HASH = "sha256:" + ("0" * 64)
REQUESTER_DID = "did:example:agent:requester-7"
WORKER_DID = "did:example:agent:worker-42"
OWNER_DID = "did:example:owner:123"
SUPPORTED_VERBS = {"ADVERTISE", "DISCOVER", "NEGOTIATE", "ROUTE", "SETTLE", "ATTEST"}
NASA_ARTEMIS_TEXT_TABLE_URL = (
    "https://eol.jsc.nasa.gov/SearchPhotos/"
    "ShowQueryResults-TextTable.pl?results=Artemis_Artemis2_all"
)
NASA_ARTEMIS_SMALL_IMAGE_URL = (
    "https://eol.jsc.nasa.gov/DatabaseImages/ESC/small/ART002/"
)
VISUAL_DHASH_THRESHOLD = 10


def configure_transaction(transaction_id: str) -> None:
    """Configure the active ATP transaction and output directories."""
    global TRANSACTION_ID, RUN_DIR, ARTIFACTS_DIR
    TRANSACTION_ID = transaction_id
    RUN_DIR = Path("runs") / TRANSACTION_ID
    ARTIFACTS_DIR = RUN_DIR / "artifacts"


# ---------------------------------------------------------------------------
# 1. ATP crypto
# ---------------------------------------------------------------------------


def canon(obj: Any) -> bytes:
    """Return ATP v0.3 canonical JSON bytes."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    """Return a full sha256: digest for raw bytes."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_json(obj: Any) -> str:
    """Return a full sha256: digest for canonical JSON."""
    return sha256_bytes(canon(obj))


def b64url_encode(data: bytes) -> str:
    """Encode bytes as unpadded base64url."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(value: str) -> bytes:
    """Decode unpadded base64url text."""
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def utc_now() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


def iso_utc(value: datetime) -> str:
    """Format a UTC datetime as ISO 8601 with a Z suffix."""
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_iso_utc(value: str) -> datetime:
    """Parse an ISO 8601 UTC timestamp with a Z suffix."""
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def nonce() -> str:
    """Return a URL-safe nonce of at least 16 characters."""
    return secrets.token_urlsafe(18)


@dataclass
class AgentIdentity:
    """ATP agent identity backed by a local Ed25519 keypair."""

    did: str
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey
    kid: str

    @classmethod
    def create(cls, did: str) -> "AgentIdentity":
        """Create a local Ed25519 identity for an ATP agent."""
        private_key = Ed25519PrivateKey.generate()
        return cls(
            did=did,
            private_key=private_key,
            public_key=private_key.public_key(),
            kid=f"{did}#key-1",
        )

    def sign(self, payload: bytes) -> str:
        """Sign canonical bytes and return an unpadded base64url signature."""
        return b64url_encode(self.private_key.sign(payload))

    def verify(self, payload: bytes, signature: str) -> bool:
        """Verify an unpadded base64url Ed25519 signature."""
        try:
            self.public_key.verify(b64url_decode(signature), payload)
            return True
        except InvalidSignature:
            return False


def export_public_key(identity: AgentIdentity) -> Dict[str, str]:
    """Export an ATP agent's public key as raw unpadded base64url bytes."""
    public_bytes = identity.public_key.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )
    return {
        "kid": identity.kid,
        "alg": "Ed25519",
        "publicKeyBase64Url": b64url_encode(public_bytes),
    }


def import_public_key(record: Dict[str, str]) -> Ed25519PublicKey:
    """Import a raw Ed25519 public key from a public-keys.json record."""
    if record.get("alg") != "Ed25519":
        raise ValueError(f"unsupported public key alg: {record.get('alg')}")
    return Ed25519PublicKey.from_public_bytes(
        b64url_decode(record["publicKeyBase64Url"])
    )


def verify_with_public_key(
    public_key: Ed25519PublicKey,
    payload: bytes,
    signature: str,
) -> bool:
    """Verify an Ed25519 signature against canonical bytes."""
    try:
        public_key.verify(b64url_decode(signature), payload)
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# 2. ATP envelope
# ---------------------------------------------------------------------------


class NonceTracker:
    """Tracks accepted ATP message nonces per issuer for replay resistance."""

    def __init__(self) -> None:
        """Create an empty nonce tracker."""
        self._seen: Dict[str, set] = {}

    def accept(self, issuer: str, value: str) -> bool:
        """Record a nonce if it has not already been used by the issuer."""
        issuer_seen = self._seen.setdefault(issuer, set())
        if value in issuer_seen:
            return False
        issuer_seen.add(value)
        return True


def envelope_signing_payload(envelope: Dict[str, Any]) -> bytes:
    """Canonicalize an envelope excluding the proofs field."""
    unsigned = dict(envelope)
    unsigned.pop("proofs", None)
    return canon(unsigned)


def make_envelope(
    issuer: AgentIdentity,
    audience: str,
    verb: str,
    transaction_id: str,
    prev: str,
    body: Dict[str, Any],
    expires_at: datetime,
) -> Dict[str, Any]:
    """Create and sign an ATP envelope using the v0.3 proof rule."""
    envelope: Dict[str, Any] = {
        "atp": ATP_VERSION,
        "verb": verb,
        "transactionId": transaction_id,
        "issuer": issuer.did,
        "audience": audience,
        "createdAt": iso_utc(utc_now()),
        "expiresAt": iso_utc(expires_at),
        "nonce": nonce(),
        "prev": prev,
        "body": body,
    }
    signature = issuer.sign(envelope_signing_payload(envelope))
    envelope["proofs"] = [
        {
            "type": "Ed25519",
            "kid": issuer.kid,
            "signature": signature,
        }
    ]
    return envelope


def require_envelope_fields(envelope: Dict[str, Any]) -> None:
    """Reject envelopes missing ATP v0.3 required fields."""
    required = {
        "atp",
        "verb",
        "transactionId",
        "issuer",
        "audience",
        "createdAt",
        "expiresAt",
        "nonce",
        "prev",
        "body",
        "proofs",
    }
    missing = sorted(required - set(envelope))
    if missing:
        raise ValueError(f"ATP envelope missing required fields: {missing}")


def verify_envelope(
    envelope: Dict[str, Any],
    expected_prev: str,
    expected_audience: str,
    public_keys: Dict[str, Ed25519PublicKey],
    nonces: NonceTracker,
    check_expiry: bool = True,
) -> bool:
    """Verify an ATP envelope signature, nonce, expiry, prev, and verb."""
    require_envelope_fields(envelope)
    if envelope["atp"] != ATP_VERSION:
        raise ValueError(f"unsupported ATP version: {envelope['atp']}")
    if envelope["transactionId"] != TRANSACTION_ID:
        raise ValueError(f"unexpected transaction id: {envelope['transactionId']}")
    if envelope["verb"] not in SUPPORTED_VERBS:
        raise ValueError(f"unsupported ATP verb: {envelope['verb']}")
    if envelope["audience"] != expected_audience:
        raise ValueError(
            f"unexpected audience: expected {expected_audience}, got {envelope['audience']}"
        )
    if envelope["prev"] != expected_prev:
        raise ValueError(f"ATP_BAD_PREV: expected {expected_prev}, got {envelope['prev']}")
    if check_expiry and parse_iso_utc(envelope["expiresAt"]) <= utc_now():
        raise ValueError("ATP_STALE: envelope expired")
    issuer = envelope["issuer"]
    if issuer not in public_keys:
        raise ValueError(f"unknown issuer: {issuer}")
    proofs = envelope["proofs"]
    if not isinstance(proofs, list) or len(proofs) != 1:
        raise ValueError("envelope must contain exactly one proof")
    proof = proofs[0]
    if proof.get("type") != "Ed25519":
        raise ValueError("unsupported proof type")
    expected_kid = f"{issuer}#key-1"
    if proof.get("kid") != expected_kid:
        raise ValueError(f"unexpected kid: {proof.get('kid')}")
    if not verify_with_public_key(
        public_keys[issuer],
        envelope_signing_payload(envelope),
        proof["signature"],
    ):
        raise ValueError("ATP_BAD_SIG: envelope signature verification failed")
    if not nonces.accept(issuer, envelope["nonce"]):
        raise ValueError(f"ATP_STALE: nonce already accepted for {issuer}")
    return True


def post_json(url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """POST JSON using urllib.request and return a decoded JSON object."""
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        raise RuntimeError(f"POST {url} failed with {exc.code}: {detail}") from exc


def get_json(url: str) -> Dict[str, Any]:
    """GET JSON using urllib.request and return a decoded JSON object."""
    with urllib.request.urlopen(url, timeout=2) as response:
        return json.loads(response.read().decode("utf-8"))


def capability_card_body(worker_did: str, port: int) -> Dict[str, Any]:
    """Build the unsigned ATP worker capability card."""
    return {
        "atp": ATP_VERSION,
        "agentId": worker_did,
        "endpoints": [
            {"transport": "http", "url": f"http://127.0.0.1:{port}/atp"}
        ],
        "capabilities": [
            "photo-organization",
            "metadata-extraction",
            "duplicate-detection",
        ],
        "proofMethods": ["Ed25519"],
        "settlementRails": ["zero-value"],
        "requiredExtensions": [],
    }


def signed_capability_card(worker: AgentIdentity, port: int) -> Dict[str, Any]:
    """Create a signed ATP capability card evidence object."""
    card = capability_card_body(worker.did, port)
    return {
        "card": card,
        "proof": {
            "type": "Ed25519",
            "kid": worker.kid,
            "signature": worker.sign(canon(card)),
        },
        "cardHash": sha256_json(card),
    }


def verify_capability_card(
    signed_card: Dict[str, Any],
    worker_public_key: Ed25519PublicKey,
) -> bool:
    """Verify a signed worker capability card and its cardHash."""
    card = signed_card["card"]
    proof = signed_card["proof"]
    expected_hash = sha256_json(card)
    if signed_card.get("cardHash") != expected_hash:
        raise ValueError("capability card hash mismatch")
    if card.get("atp") != ATP_VERSION:
        raise ValueError("capability card ATP version mismatch")
    if card.get("agentId") != WORKER_DID:
        raise ValueError("capability card worker DID mismatch")
    if "photo-organization" not in card.get("capabilities", []):
        raise ValueError("capability card missing photo-organization")
    if proof.get("type") != "Ed25519":
        raise ValueError("capability card proof type mismatch")
    if proof.get("kid") != f"{WORKER_DID}#key-1":
        raise ValueError("capability card kid mismatch")
    if not verify_with_public_key(worker_public_key, canon(card), proof["signature"]):
        raise ValueError("capability card signature invalid")
    return True


# ---------------------------------------------------------------------------
# 3. ATP event log
# ---------------------------------------------------------------------------


class EventLog:
    """Append-only ATP event log with monotone hash chaining."""

    def __init__(self, path: Path, envelopes_path: Path) -> None:
        """Create an empty transcript at the requested path."""
        self.path = path
        self.envelopes_path = envelopes_path
        self.events: List[Dict[str, Any]] = []
        self.envelopes: List[Dict[str, Any]] = []
        self.current_root = GENESIS_HASH
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("", encoding="utf-8")
        self.envelopes_path.write_text("", encoding="utf-8")

    def append(self, envelope: Dict[str, Any]) -> Dict[str, Any]:
        """Append one accepted ATP envelope to the transcript."""
        body_hash = sha256_json(envelope["body"])
        proof = envelope["proofs"][0]
        event_hash = self.compute_event_hash(
            envelope["prev"],
            envelope["verb"],
            envelope["issuer"],
            body_hash,
            envelope["createdAt"],
            envelope["nonce"],
        )
        event = {
            "verb": envelope["verb"],
            "actor": envelope["issuer"],
            "prev": envelope["prev"],
            "bodyHash": body_hash,
            "time": envelope["createdAt"],
            "nonce": envelope["nonce"],
            "sig": proof["signature"],
            "eventHash": event_hash,
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
        with self.envelopes_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(envelope, sort_keys=True) + "\n")
        self.events.append(event)
        self.envelopes.append(envelope)
        self.current_root = event_hash
        return event

    @staticmethod
    def compute_event_hash(
        prev: str,
        verb: str,
        actor: str,
        body_hash: str,
        event_time: str,
        event_nonce: str,
    ) -> str:
        """Compute an ATP event hash from the v0.3 concatenation rule."""
        payload = (prev + verb + actor + body_hash + event_time + event_nonce).encode(
            "utf-8"
        )
        return sha256_bytes(payload)

    def root_before_last(self) -> str:
        """Return the transcript root immediately before the latest event."""
        if len(self.events) < 2:
            return GENESIS_HASH
        return self.events[-2]["eventHash"]


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    """Read a JSONL file into a list of objects."""
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


# ---------------------------------------------------------------------------
# 4. ATP state machine
# ---------------------------------------------------------------------------


class StateMachine:
    """ATP v0.3 transaction state machine for the required demo verbs."""

    def __init__(self) -> None:
        """Create a new ATP transaction state machine."""
        self.state = "new"

    def validate(self, verb: str, body: Dict[str, Any]) -> None:
        """Reject invalid state transitions before an event is appended."""
        next_state = self._next_state(verb, body)
        if next_state is None:
            raise ValueError(f"ATP_BAD_STATE: {self.state} cannot accept {verb}")

    def apply(self, verb: str, body: Dict[str, Any]) -> None:
        """Apply a validated ATP state transition."""
        next_state = self._next_state(verb, body)
        if next_state is None:
            raise ValueError(f"ATP_BAD_STATE: {self.state} cannot accept {verb}")
        self.state = next_state

    def enter_executing(self) -> None:
        """Apply the internal worker transition from routed to executing."""
        if self.state != "routed":
            raise ValueError(f"cannot enter executing from {self.state}")
        self.state = "executing"

    def _next_state(self, verb: str, body: Dict[str, Any]) -> Optional[str]:
        if self.state == "new" and verb == "DISCOVER":
            return "discovered"
        if (
            self.state == "discovered"
            and verb == "NEGOTIATE"
            and body.get("type") == "offer"
        ):
            return "negotiating"
        if (
            self.state == "negotiating"
            and verb == "NEGOTIATE"
            and body.get("type") == "accept"
        ):
            return "negotiated"
        if self.state == "negotiated" and verb == "ROUTE":
            return "routed"
        if self.state == "executing" and verb == "SETTLE":
            return "settled"
        if self.state == "settled" and verb == "ATTEST":
            return "attested"
        return None


# ---------------------------------------------------------------------------
# 5. ATP lease guard
# ---------------------------------------------------------------------------


class LeaseGuard:
    """Enforces ATP context leases over local file reads and writes."""

    def __init__(self, leases: List[Dict[str, Any]], access_log_path: Path) -> None:
        """Create a lease guard and initialize its audit log."""
        self.leases = leases
        self.access_log_path = access_log_path
        self.accesses: List[Dict[str, Any]] = []
        self.access_log_path.write_text("", encoding="utf-8")

    def read_text(self, path: Path) -> str:
        """Read UTF-8 text only when an active read lease permits it."""
        if not self._authorize("read", path):
            raise PermissionError(f"read denied by ATP lease guard: {path}")
        return path.read_text(encoding="utf-8")

    def read_bytes(self, path: Path) -> bytes:
        """Read bytes only when an active read lease permits it."""
        if not self._authorize("read", path):
            raise PermissionError(f"read denied by ATP lease guard: {path}")
        return path.read_bytes()

    def write_text(self, path: Path, text: str) -> bool:
        """Write UTF-8 text only when an active write lease permits it."""
        if not self._authorize("write", path):
            return False
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return True

    def write_bytes(self, path: Path, data: bytes) -> bool:
        """Write bytes only when an active write lease permits it."""
        if not self._authorize("write", path):
            return False
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return True

    def passed(self, original_files_unchanged: bool) -> bool:
        """Return True when all required lease-guard criteria passed."""
        denied = [entry for entry in self.accesses if not entry["allowed"]]
        denied_write_observed = any(
            entry["operation"] == "write"
            and not entry["allowed"]
            and entry["path"].endswith("illegal-worker-write.txt")
            for entry in self.accesses
        )
        only_expected_denials = all(
            entry["path"].endswith("illegal-worker-write.txt") for entry in denied
        )
        legitimate_reads = any(
            entry["operation"] == "read" and entry["allowed"] for entry in self.accesses
        )
        legitimate_writes = any(
            entry["operation"] == "write" and entry["allowed"] for entry in self.accesses
        )
        return (
            denied_write_observed
            and only_expected_denials
            and legitimate_reads
            and legitimate_writes
            and original_files_unchanged
        )

    def denied_write_observed(self) -> bool:
        """Return True when the intentional bad write was denied."""
        return any(
            entry["operation"] == "write"
            and not entry["allowed"]
            and entry["path"].endswith("illegal-worker-write.txt")
            for entry in self.accesses
        )

    def _authorize(self, operation: str, path: Path) -> bool:
        resolved_path = path.resolve()
        now = utc_now()
        fallback_reason = "no active lease permits operation"
        for lease in self.leases:
            lease_id = lease["id"]
            if operation not in lease["operations"]:
                fallback_reason = "operation not listed in lease"
                continue
            ttl = lease["ttl"]
            if not (parse_iso_utc(ttl["start"]) <= now <= parse_iso_utc(ttl["end"])):
                fallback_reason = "current time outside lease ttl"
                continue
            boundary = Path(lease["boundary"]).resolve()
            if not path_is_under(resolved_path, boundary):
                fallback_reason = "path outside lease boundary"
                continue
            self._log(lease_id, operation, resolved_path, True, "allowed by active lease")
            return True
        self._log("none", operation, resolved_path, False, fallback_reason)
        return False

    def _log(
        self,
        lease_id: str,
        operation: str,
        path: Path,
        allowed: bool,
        reason: str,
    ) -> None:
        entry = {
            "time": iso_utc(utc_now()),
            "leaseId": lease_id,
            "operation": operation,
            "path": str(path),
            "allowed": allowed,
            "reason": reason,
        }
        with self.access_log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")
        self.accesses.append(entry)


def path_is_under(path: Path, boundary: Path) -> bool:
    """Return True when path is inside or equal to boundary."""
    path_text = str(path.resolve())
    boundary_text = str(boundary.resolve())
    return os.path.commonpath([path_text, boundary_text]) == boundary_text


def sign_lease(lease: Dict[str, Any], owner: AgentIdentity) -> Dict[str, Any]:
    """Sign an ATP context lease, excluding the sig field."""
    unsigned = dict(lease)
    unsigned.pop("sig", None)
    signed = dict(unsigned)
    signed["sig"] = owner.sign(canon(unsigned))
    return signed


def verify_lease(
    lease: Dict[str, Any],
    owner_public_key: Ed25519PublicKey,
    check_ttl: bool = True,
) -> bool:
    """Verify a signed ATP context lease and its TTL."""
    signature = lease.get("sig")
    if not signature:
        raise ValueError(f"lease {lease.get('id')} missing sig")
    unsigned = dict(lease)
    unsigned.pop("sig", None)
    if not verify_with_public_key(owner_public_key, canon(unsigned), signature):
        raise ValueError(f"lease {lease.get('id')} signature invalid")
    ttl = lease["ttl"]
    now = utc_now()
    if check_ttl and not (
        parse_iso_utc(ttl["start"]) <= now <= parse_iso_utc(ttl["end"])
    ):
        raise ValueError(f"lease {lease.get('id')} outside ttl")
    parse_iso_utc(ttl["start"])
    parse_iso_utc(ttl["end"])
    return True


def verify_leases(
    leases: List[Dict[str, Any]],
    requester_public_key: Ed25519PublicKey,
    check_ttl: bool = True,
) -> bool:
    """Verify all route leases before worker execution."""
    required_ids = {"lease_photos_read_001", "lease_stage_write_001"}
    observed_ids = {lease.get("id") for lease in leases}
    if observed_ids != required_ids:
        raise ValueError(f"unexpected lease ids: {observed_ids}")
    for lease in leases:
        verify_lease(lease, requester_public_key, check_ttl=check_ttl)
    return True


# ---------------------------------------------------------------------------
# 6. ATP receipt
# ---------------------------------------------------------------------------


def receipt_hash_body(receipt: Dict[str, Any]) -> Dict[str, Any]:
    """Return the Proof of Cognition body used for receiptHash."""
    body = dict(receipt)
    body.pop("receiptHash", None)
    body.pop("signatures", None)
    return body


def receipt_signature_body(receipt: Dict[str, Any]) -> Dict[str, Any]:
    """Return the signed Proof of Cognition body, excluding signatures."""
    body = dict(receipt)
    body.pop("signatures", None)
    return body


def artifact_records(artifact_dir: Path) -> List[Dict[str, Any]]:
    """Describe produced artifacts with path, hash, size, and media type."""
    media_types = {
        "manifest.json": "application/json",
        "album-plan.json": "application/json",
        "duplicate-candidates.csv": "text/csv",
    }
    records: List[Dict[str, Any]] = []
    for name in ["manifest.json", "album-plan.json", "duplicate-candidates.csv"]:
        path = artifact_dir / name
        if not path.is_file():
            raise ValueError(f"missing artifact file: {name}")
        data = path.read_bytes()
        records.append(
            {
                "path": name,
                "sha256": sha256_bytes(data),
                "sizeBytes": len(data),
                "mediaType": media_types[name],
            }
        )
    return records


def create_receipt(
    worker: AgentIdentity,
    intent: Dict[str, Any],
    leases: List[Dict[str, Any]],
    settlement: Dict[str, Any],
    event_root: str,
    photo_dir: Path,
    staging_dir: Path,
    originals_modified: bool,
) -> Dict[str, Any]:
    """Create and sign a Proof of Cognition receipt."""
    receipt: Dict[str, Any] = {
        "receiptType": "ProofOfCognition",
        "atp": ATP_VERSION,
        "transactionId": TRANSACTION_ID,
        "requested": {
            "intent": intent,
            "constraints": intent["constraints"],
            "success": intent["success"],
            "budget": intent["budget"],
            "deadline": intent["deadline"],
        },
        "accessed": {
            "leases": [lease["id"] for lease in leases],
            "resources": [str(photo_dir.resolve()), str(staging_dir.resolve())],
        },
        "changed": {
            "artifacts": artifact_records(staging_dir),
            "externalState": "staging-directory-only",
            "originalsModified": originals_modified,
        },
        "approved": {
            "by": OWNER_DID,
            "method": "human-approval-simulated",
            "time": iso_utc(utc_now()),
        },
        "paid": settlement,
        # Preferred ATP v0.3 demo rule: the receipt commits to the SETTLE root.
        "eventRoot": event_root,
    }
    receipt["receiptHash"] = sha256_json(receipt_hash_body(receipt))
    signature = worker.sign(canon(receipt_signature_body(receipt)))
    receipt["signatures"] = [
        {
            "type": "Ed25519",
            "kid": worker.kid,
            "signature": signature,
        }
    ]
    return receipt


def verify_receipt(
    receipt: Dict[str, Any],
    worker_public_key: Ed25519PublicKey,
) -> bool:
    """Verify receiptHash and the worker's Proof of Cognition signature."""
    expected_hash = sha256_json(receipt_hash_body(receipt))
    if receipt.get("receiptHash") != expected_hash:
        raise ValueError(
            f"receiptHash mismatch: expected {expected_hash}, got {receipt.get('receiptHash')}"
        )
    signatures = receipt.get("signatures")
    if not isinstance(signatures, list) or len(signatures) != 1:
        raise ValueError("receipt must contain exactly one signature")
    signature = signatures[0]
    if signature.get("kid") != f"{WORKER_DID}#key-1":
        raise ValueError("receipt signature kid mismatch")
    if not verify_with_public_key(
        worker_public_key,
        canon(receipt_signature_body(receipt)),
        signature["signature"],
    ):
        raise ValueError("receipt signature invalid")
    return True


# ---------------------------------------------------------------------------
# 7. Worker FastAPI app
# ---------------------------------------------------------------------------


class WorkerContext:
    """Mutable local context owned by the localhost worker agent."""

    def __init__(
        self,
        worker: AgentIdentity,
        requester: AgentIdentity,
        event_log: EventLog,
        state_machine: StateMachine,
        nonces: NonceTracker,
        public_keys: Dict[str, Ed25519PublicKey],
        access_log_path: Path,
        photo_dir: Path,
        artifact_dir: Path,
        port: int,
    ) -> None:
        """Create the worker context shared by the FastAPI handlers."""
        self.worker = worker
        self.requester = requester
        self.event_log = event_log
        self.state_machine = state_machine
        self.nonces = nonces
        self.public_keys = public_keys
        self.access_log_path = access_log_path
        self.photo_dir = photo_dir
        self.artifact_dir = artifact_dir
        self.staging_dir = artifact_dir
        self.port = port
        self.offer_body: Optional[Dict[str, Any]] = None
        self.accept_body: Optional[Dict[str, Any]] = None
        self.final_contract: Optional[Dict[str, Any]] = None
        self.final_contract_hash: Optional[str] = None
        self.intent: Optional[Dict[str, Any]] = None
        self.leases: List[Dict[str, Any]] = []
        self.lease_guard: Optional[LeaseGuard] = None
        self.settlement: Optional[Dict[str, Any]] = None
        self.original_hashes_before: Dict[str, str] = {}
        self.original_hashes_after: Dict[str, str] = {}

    def capability_card(self) -> Dict[str, Any]:
        """Return the worker's signed ATP discovery document."""
        return signed_capability_card(self.worker, self.port)

    def accept_inbound(self, envelope: Dict[str, Any]) -> None:
        """Validate, state-check, and append an inbound ATP envelope."""
        verify_envelope(
            envelope=envelope,
            expected_prev=self.event_log.current_root,
            expected_audience=self.worker.did,
            public_keys=self.public_keys,
            nonces=self.nonces,
        )
        self.state_machine.validate(envelope["verb"], envelope["body"])
        self.event_log.append(envelope)
        self.state_machine.apply(envelope["verb"], envelope["body"])

    def handle_discover(self, envelope: Dict[str, Any]) -> Dict[str, Any]:
        """Accept DISCOVER and return the worker capability card."""
        self.accept_inbound(envelope)
        if envelope["body"].get("capabilityCardHash") != self.capability_card()["cardHash"]:
            raise ValueError("DISCOVER capabilityCardHash does not match worker card")
        return {"capabilityCard": self.capability_card()}

    def handle_negotiate(self, envelope: Dict[str, Any]) -> Dict[str, Any]:
        """Accept a NEGOTIATE offer and return a signed accept envelope."""
        self.accept_inbound(envelope)
        self.offer_body = envelope["body"]
        self.accept_body = {
            "type": "accept",
            "accepted": True,
            "contractHash": sha256_json(self.offer_body),
            "worker": self.worker.did,
        }
        self.final_contract = {
            "offer": self.offer_body,
            "accept": self.accept_body,
        }
        self.final_contract_hash = sha256_json(self.final_contract)
        response = make_envelope(
            issuer=self.worker,
            audience=self.requester.did,
            verb="NEGOTIATE",
            transaction_id=TRANSACTION_ID,
            prev=self.event_log.current_root,
            body=self.accept_body,
            expires_at=utc_now() + timedelta(hours=1),
        )
        return {"envelope": response}

    def handle_route(self, envelope: Dict[str, Any]) -> Dict[str, Any]:
        """Accept ROUTE, execute under leases, and return SETTLE."""
        self.accept_inbound(envelope)
        self.state_machine.enter_executing()
        route_body = envelope["body"]
        if self.final_contract_hash is None:
            raise ValueError("route received before final contract hash exists")
        if route_body["contractHash"] != self.final_contract_hash:
            raise ValueError("ROUTE contractHash does not match final contract")
        work_session = route_body["workSession"]
        if Path(work_session["stagingDirectory"]).resolve() != self.staging_dir.resolve():
            raise ValueError("unexpected staging directory")
        if Path(work_session["artifactDirectory"]).resolve() != self.artifact_dir.resolve():
            raise ValueError("unexpected artifact directory")
        leases = route_body["leases"]
        verify_leases(leases, self.requester.public_key)
        self.intent = route_body["intent"]
        self.leases = leases
        self.lease_guard = LeaseGuard(leases, self.access_log_path)
        self.execute_photo_work()
        self.settlement = {
            "rail": "zero-value",
            "amount": "0",
            "asset": "none",
            "payer": self.requester.did,
            "payee": self.worker.did,
            "condition": "receipt",
            "proofOfPayment": "waived",
            "refundPolicy": "not-applicable",
            "disputePolicy": "local-demo",
        }
        response = make_envelope(
            issuer=self.worker,
            audience=self.requester.did,
            verb="SETTLE",
            transaction_id=TRANSACTION_ID,
            prev=self.event_log.current_root,
            body=self.settlement,
            expires_at=utc_now() + timedelta(hours=1),
        )
        return {"envelope": response}

    def execute_photo_work(self) -> None:
        """Run the canonical ATP photo-organization workload under leases."""
        if self.lease_guard is None or self.intent is None:
            raise ValueError("lease guard and intent must exist before execution")
        metadata_path = self.photo_dir / "metadata.json"
        metadata = json.loads(self.lease_guard.read_text(metadata_path))
        photos = metadata["photos"]
        dedupe = metadata.get("dedupe", {"mode": "content-hash"})
        dedupe_mode = dedupe.get("mode", "content-hash")
        visual_threshold = int(
            dedupe.get("hammingDistanceThreshold", VISUAL_DHASH_THRESHOLD)
        )
        for photo in photos:
            photo_path = self.photo_dir / photo["filename"]
            data = self.lease_guard.read_bytes(photo_path)
            observed_hash = sha256_bytes(data)
            if observed_hash != photo["contentHash"]:
                raise ValueError(f"content hash mismatch for {photo['filename']}")
            if dedupe_mode == "visual-dhash":
                photo["visualHash"] = visual_dhash_from_bytes(data)

        duplicate_rows = find_duplicates(photos, dedupe_mode, visual_threshold)
        albums = build_album_plan(photos)
        unique_photos = [
            photo["filename"] for photo in photos if not photo.get("duplicateOf")
        ]
        manifest = {
            "transactionId": TRANSACTION_ID,
            "generatedAt": iso_utc(utc_now()),
            "dataset": metadata.get("dataset", {"name": "mock photo library"}),
            "dedupe": {
                **dedupe,
                "mode": dedupe_mode,
                "duplicateCandidateCount": len(duplicate_rows),
                "uniquePhotoCount": len(unique_photos),
                "inputPhotoCount": len(photos),
            },
            "photos": photos,
            "uniquePhotos": sorted(unique_photos),
            "proposedAlbums": [
                {
                    "album": album["album"],
                    "targetFolder": album["targetFolder"],
                    "photoCount": len(album["photos"]),
                    "uniquePhotoCount": len(album["uniquePhotos"]),
                }
                for album in albums
            ],
            "leaseIdsUsed": [lease["id"] for lease in self.leases],
        }
        album_plan = {"albums": albums}
        duplicate_csv = duplicate_candidates_csv(duplicate_rows)

        writes = {
            "manifest.json": json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            "album-plan.json": json.dumps(album_plan, indent=2, sort_keys=True) + "\n",
            "duplicate-candidates.csv": duplicate_csv,
        }
        for filename, text in writes.items():
            ok = self.lease_guard.write_text(self.staging_dir / filename, text)
            if not ok:
                raise PermissionError(f"legitimate artifact write denied: {filename}")

        # ATP v0.3 context lease guard: intentionally exercise a denied write.
        denied = self.lease_guard.write_text(
            self.photo_dir / "illegal-worker-write.txt",
            "this write must be denied by the ATP lease guard\n",
        )
        if denied:
            raise AssertionError("intentional bad write unexpectedly allowed")

    def build_attest_envelope(self, originals_modified: bool) -> Dict[str, Any]:
        """Create the worker's ATTEST envelope after SETTLE is accepted."""
        if self.intent is None or self.settlement is None or not self.leases:
            raise ValueError("cannot attest before route execution and settlement")
        receipt = create_receipt(
            worker=self.worker,
            intent=self.intent,
            leases=self.leases,
            settlement=self.settlement,
            event_root=self.event_log.current_root,
            photo_dir=self.photo_dir,
            staging_dir=self.staging_dir,
            originals_modified=originals_modified,
        )
        return make_envelope(
            issuer=self.worker,
            audience=self.requester.did,
            verb="ATTEST",
            transaction_id=TRANSACTION_ID,
            prev=self.event_log.current_root,
            body=receipt,
            expires_at=utc_now() + timedelta(hours=1),
        )


def create_worker_app(context: WorkerContext) -> FastAPI:
    """Create the FastAPI worker app for ATP-over-localhost."""
    app = FastAPI()

    @app.get("/.well-known/atp.json")
    async def atp_card() -> Dict[str, Any]:
        return context.capability_card()

    @app.post("/atp")
    async def atp_endpoint(request: Request) -> Dict[str, Any]:
        try:
            envelope = await request.json()
            verb = envelope.get("verb")
            if verb == "DISCOVER":
                return context.handle_discover(envelope)
            if verb == "NEGOTIATE":
                return context.handle_negotiate(envelope)
            if verb == "ROUTE":
                return context.handle_route(envelope)
            raise ValueError(f"worker does not accept inbound {verb}")
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    return app


def find_worker_port(preferred: int = 8765) -> int:
    """Return a fixed localhost port unless it is already unavailable."""
    if port_available(preferred):
        return preferred
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def port_available(port: int) -> bool:
    """Return True when a localhost port can be bound."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def start_worker_server(context: WorkerContext) -> Tuple[uvicorn.Server, threading.Thread]:
    """Start the FastAPI ATP worker in a background thread."""
    app = create_worker_app(context)
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=context.port,
        log_level="critical",
        access_log=False,
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    wait_for_capability_card(context.port)
    return server, thread


def wait_for_capability_card(port: int) -> None:
    """Wait until the worker's ATP discovery document responds."""
    url = f"http://127.0.0.1:{port}/.well-known/atp.json"
    deadline = time.time() + 10
    last_error: Optional[BaseException] = None
    while time.time() < deadline:
        try:
            get_json(url)
            return
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            last_error = exc
            time.sleep(0.05)
    raise RuntimeError(f"worker server did not start: {last_error}")


def stop_worker_server(server: uvicorn.Server, thread: threading.Thread) -> None:
    """Ask uvicorn to shut down and wait briefly for its thread."""
    server.should_exit = True
    thread.join(timeout=5)


# ---------------------------------------------------------------------------
# 8. Demo orchestration
# ---------------------------------------------------------------------------


def reset_run_dir() -> None:
    """Remove and recreate the ATP demo run directory."""
    if RUN_DIR.exists():
        shutil.rmtree(RUN_DIR)
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)


def write_json(path: Path, obj: Any) -> None:
    """Write stable, readable JSON to a path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_json(path: Path) -> Any:
    """Load JSON from a path."""
    return json.loads(path.read_text(encoding="utf-8"))


def write_public_keys(requester: AgentIdentity, worker: AgentIdentity, path: Path) -> None:
    """Persist public key evidence for offline verification."""
    write_json(
        path,
        {
            requester.did: export_public_key(requester),
            worker.did: export_public_key(worker),
        },
    )


def load_public_keys(path: Path) -> Dict[str, Ed25519PublicKey]:
    """Load persisted public keys for offline verification."""
    records = load_json(path)
    public_keys: Dict[str, Ed25519PublicKey] = {}
    for did, record in records.items():
        expected_kid = f"{did}#key-1"
        if record.get("kid") != expected_kid:
            raise ValueError(f"public key kid mismatch for {did}")
        public_keys[did] = import_public_key(record)
    return public_keys


def download_url_bytes(url: str) -> bytes:
    """Download bytes with a clear ATP demo user agent."""
    last_error: Optional[BaseException] = None
    for attempt in range(1, 4):
        try:
            request = urllib.request.Request(
                url,
                headers={"User-Agent": "CYPHES-ATP-Receipt-Zero/0.1"},
            )
            with urllib.request.urlopen(request, timeout=15) as response:
                return response.read()
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = exc
            if attempt < 3:
                time.sleep(1.0)
    raise RuntimeError(f"download failed for {url}: {last_error}")


def create_mock_photo_library() -> Path:
    """Create the local mock photo library and sidecar metadata."""
    photo_dir = Path("/tmp/mock_photos_atp").resolve()
    if photo_dir.exists():
        shutil.rmtree(photo_dir)
    photo_dir.mkdir(parents=True, exist_ok=True)
    photo_specs = [
        ("img_0001.jpg", "2026-05-21", "WAGMI City Launch", "launch-a"),
        ("img_0002.jpg", "2026-05-21", "WAGMI City Launch", "launch-b"),
        ("img_0003.jpg", "2026-05-21", "WAGMI City Launch", "launch-a"),
        ("img_0004.jpg", "2026-05-22", "Planet X Briefing", "briefing-a"),
        ("img_0005.jpg", "2026-05-22", "Planet X Briefing", "briefing-b"),
        ("img_0006.jpg", "2026-05-22", "Planet X Briefing", "briefing-b"),
        ("img_0007.jpg", "2026-05-23", "Resistance Field Test", "field-a"),
        ("img_0008.jpg", "2026-05-23", "Resistance Field Test", "field-b"),
        ("img_0009.jpg", "2026-05-23", "Resistance Field Test", "field-c"),
        ("img_0010.jpg", "2026-05-24", "EMC Archive", "archive-a"),
    ]
    photos: List[Dict[str, Any]] = []
    for filename, created, event_label, content_group in photo_specs:
        data = f"CYPHES mock jpg bytes::{content_group}\n".encode("utf-8")
        (photo_dir / filename).write_bytes(data)
        photos.append(
            {
                "filename": filename,
                "createdDate": created,
                "eventLabel": event_label,
                "contentGroup": content_group,
                "contentHash": sha256_bytes(data),
            }
        )
    write_json(photo_dir / "metadata.json", {"photos": photos})
    return photo_dir


def parse_nasa_artemis_rows(html_text: str) -> List[Dict[str, str]]:
    """Parse Artemis II table rows from NASA Gateway text-table HTML."""
    text = re.sub(r"<[^>]+>", " ", html_text)
    text = re.sub(r"\s+", " ", text)
    pattern = re.compile(
        r"(ART002-E-\d+)\s+(\d{8})\s+"
        r"(-?\d+(?:\.\d+)?)\s+(-?\d+(?:\.\d+)?)"
    )
    rows: List[Dict[str, str]] = []
    seen: set = set()
    for match in pattern.finditer(text):
        photo_id = match.group(1)
        if photo_id in seen:
            continue
        seen.add(photo_id)
        rows.append(
            {
                "photoId": photo_id,
                "date": match.group(2),
                "latitude": match.group(3),
                "longitude": match.group(4),
            }
        )
    if not rows:
        raise ValueError("NASA Artemis table yielded no photo rows")
    return rows


def select_spread_rows(
    rows: List[Dict[str, str]],
    limit: int,
) -> List[Dict[str, str]]:
    """Select rows evenly across the public archive instead of sequential frames."""
    if limit >= len(rows):
        return rows
    if limit == 1:
        return [rows[0]]
    indexes = [
        round(index * (len(rows) - 1) / (limit - 1))
        for index in range(limit)
    ]
    selected: List[Dict[str, str]] = []
    seen: set = set()
    for index in indexes:
        row = rows[index]
        photo_id = row["photoId"]
        if photo_id in seen:
            continue
        seen.add(photo_id)
        selected.append(row)
    return selected


def create_nasa_artemis_photo_library(limit: int) -> Path:
    """Create a local Receipt Zero library from NASA Artemis II public images."""
    if limit < 1:
        raise ValueError("Receipt Zero image limit must be at least 1")
    photo_dir = Path("/tmp/receipt_zero_nasa_artemis").resolve()
    if photo_dir.exists():
        shutil.rmtree(photo_dir)
    photo_dir.mkdir(parents=True, exist_ok=True)

    html_text = download_url_bytes(NASA_ARTEMIS_TEXT_TABLE_URL).decode("utf-8", "replace")
    all_rows = parse_nasa_artemis_rows(html_text)
    rows = select_spread_rows(all_rows, limit)
    photos: List[Dict[str, Any]] = []
    for row in rows:
        photo_id = row["photoId"]
        filename = f"{photo_id}.JPG"
        source_url = f"{NASA_ARTEMIS_SMALL_IMAGE_URL}{filename}"
        data = download_url_bytes(source_url)
        (photo_dir / filename).write_bytes(data)
        created = f"{row['date'][0:4]}-{row['date'][4:6]}-{row['date'][6:8]}"
        photos.append(
            {
                "filename": filename,
                "createdDate": created,
                "eventLabel": "NASA Artemis II public image archive",
                "contentGroup": f"nasa-artemis-ii-{created}",
                "contentHash": sha256_bytes(data),
                "sourcePhotoId": photo_id,
                "sourceImageUrl": source_url,
                "sourcePhotoPageUrl": (
                    "https://eol.jsc.nasa.gov/SearchPhotos/photo.pl?"
                    f"mission=ART002&roll=E&frame={photo_id.rsplit('-', 1)[-1]}"
                ),
                "latitude": row["latitude"],
                "longitude": row["longitude"],
            }
        )

    write_json(
        photo_dir / "metadata.json",
        {
            "dataset": {
                "name": "NASA Artemis II public image archive",
                "source": NASA_ARTEMIS_TEXT_TABLE_URL,
                "imageBaseUrl": NASA_ARTEMIS_SMALL_IMAGE_URL,
                "imageResolution": "ESC/small",
                "requestedLimit": limit,
                "selectedCount": len(photos),
                "availableCount": len(all_rows),
                "selectionMethod": "evenly-spaced-across-source-results",
                "attribution": (
                    "Image courtesy of the Earth Science and Remote Sensing Unit, "
                    "NASA Johnson Space Center."
                ),
            },
            "dedupe": {
                "mode": "visual-dhash",
                "algorithm": "64-bit difference hash over grayscale 9x8 pixels",
                "hammingDistanceThreshold": VISUAL_DHASH_THRESHOLD,
                "selectionPolicy": "keep-first-observed-photo-per-visual-cluster",
            },
            "photos": photos,
        },
    )
    return photo_dir


def iter_photo_files(photo_dir: Path) -> List[Path]:
    """Return source photo files using case-insensitive JPG matching."""
    return sorted(
        path
        for path in photo_dir.iterdir()
        if path.is_file() and path.suffix.lower() == ".jpg"
    )


def original_photo_hashes(photo_dir: Path) -> Dict[str, str]:
    """Hash all original source JPG files."""
    hashes: Dict[str, str] = {}
    for path in iter_photo_files(photo_dir):
        hashes[path.name] = sha256_bytes(path.read_bytes())
    return hashes


def originals_unchanged(before: Dict[str, str], photo_dir: Path) -> bool:
    """Return True when every original mock jpg hash is unchanged."""
    return before == original_photo_hashes(photo_dir)


def visual_dhash_from_bytes(data: bytes) -> str:
    """Compute a 64-bit visual difference hash for near-duplicate detection."""
    try:
        from PIL import Image
    except ImportError as exc:
        raise RuntimeError(
            "Receipt Zero visual dedupe requires Pillow. "
            "Install it with: python3 -m pip install Pillow"
        ) from exc
    with Image.open(io.BytesIO(data)) as image:
        grayscale = image.convert("L").resize((9, 8))
        pixels = list(grayscale.getdata())
    value = 0
    for y in range(8):
        for x in range(8):
            left = pixels[y * 9 + x]
            right = pixels[y * 9 + x + 1]
            value = (value << 1) | int(left > right)
    return f"{value:016x}"


def hamming_distance_hex(left: str, right: str) -> int:
    """Return the bit distance between two equal-width hexadecimal hashes."""
    return bin(int(left, 16) ^ int(right, 16)).count("1")


def build_intent(dataset_name: str = "mock") -> Dict[str, Any]:
    """Create the requester ATP intent for a photo organization transaction."""
    deadline = utc_now() + timedelta(hours=1)
    if dataset_name == "nasa-artemis":
        goal = (
            "Audit NASA Artemis II public image archive for visual duplicate "
            "clusters and produce a verifiable unique-image manifest"
        )
        success = "public-receipt-verifies-dataset-artifacts"
    else:
        goal = "Organize photo library into dated event albums"
        success = "owner-approves-staged-manifest"
    return {
        "goal": goal,
        "constraints": ["do-not-delete-originals", "stage-changes-first"],
        "success": success,
        "budget": {"amount": "0", "asset": "none"},
        "deadline": iso_utc(deadline),
    }


def build_offer_body() -> Dict[str, Any]:
    """Create the ATP NEGOTIATE offer body."""
    return {
        "type": "offer",
        "scope": "organize, detect duplicates, create album plan",
        "deliverables": [
            "manifest.json",
            "album-plan.json",
            "duplicate-candidates.csv",
        ],
        "leasesRequired": ["read-metadata", "write-staging"],
        "settlement": {
            "rail": "zero-value",
            "amount": "0",
            "asset": "none",
            "condition": "receipt",
        },
        "acceptance": {
            "method": "human-approval",
            "simulated": True,
        },
    }


def build_leases(
    requester: AgentIdentity,
    photo_dir: Path,
    staging_dir: Path,
) -> List[Dict[str, Any]]:
    """Create and sign the two ATP context leases."""
    start = iso_utc(utc_now())
    end = iso_utc(utc_now() + timedelta(hours=1))
    leases = [
        {
            "id": "lease_photos_read_001",
            "resourceRef": str(photo_dir.resolve()),
            "operations": ["read"],
            "ttl": {"start": start, "end": end},
            "purpose": "photo-organization",
            "boundary": str(photo_dir.resolve()),
            "retention": "no-retention",
            "audit": True,
            "nonce": nonce(),
        },
        {
            "id": "lease_stage_write_001",
            "resourceRef": str(staging_dir.resolve()),
            "operations": ["write"],
            "ttl": {"start": start, "end": end},
            "purpose": "stage-reversible-organization-plan",
            "boundary": str(staging_dir.resolve()),
            "retention": "retain-artifacts-delete-session",
            "audit": True,
            "nonce": nonce(),
        },
    ]
    return [sign_lease(lease, requester) for lease in leases]


def build_album_plan(photos: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Group photos by event/date into proposed albums."""
    grouped: Dict[Tuple[str, str], Dict[str, List[str]]] = {}
    for photo in photos:
        key = (photo["createdDate"], photo["eventLabel"])
        group = grouped.setdefault(key, {"photos": [], "uniquePhotos": []})
        group["photos"].append(photo["filename"])
        if not photo.get("duplicateOf"):
            group["uniquePhotos"].append(photo["filename"])
    albums: List[Dict[str, Any]] = []
    for (created, event_label), group in sorted(grouped.items()):
        folder = f"{created}_{slug(event_label)}"
        albums.append(
            {
                "album": event_label,
                "targetFolder": folder,
                "photos": sorted(group["photos"]),
                "uniquePhotos": sorted(group["uniquePhotos"]),
            }
        )
    return albums


def find_exact_duplicates(photos: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Find duplicate candidates by identical content hash."""
    by_hash: Dict[str, List[str]] = {}
    for photo in photos:
        by_hash.setdefault(photo["contentHash"], []).append(photo["filename"])
    rows: List[Dict[str, Any]] = []
    for content_hash, filenames in sorted(by_hash.items()):
        sorted_names = sorted(filenames)
        if len(sorted_names) < 2:
            continue
        anchor = sorted_names[0]
        for other in sorted_names[1:]:
            rows.append(
                {
                    "photo_a": anchor,
                    "photo_b": other,
                    "content_hash": content_hash,
                    "confidence": "1.0",
                }
            )
    return rows


def find_visual_duplicates(
    photos: List[Dict[str, Any]],
    threshold: int,
) -> List[Dict[str, Any]]:
    """Cluster visually similar photos by dHash distance and keep one representative."""
    rows: List[Dict[str, Any]] = []
    representatives: List[Dict[str, Any]] = []
    for photo in photos:
        visual_hash = photo["visualHash"]
        best: Optional[Tuple[Dict[str, Any], int]] = None
        for representative in representatives:
            distance = hamming_distance_hex(visual_hash, representative["visualHash"])
            if distance <= threshold and (best is None or distance < best[1]):
                best = (representative, distance)
        if best is None:
            photo["duplicateOf"] = None
            representatives.append(photo)
            continue
        representative, distance = best
        photo["duplicateOf"] = representative["filename"]
        confidence = max(0.0, 1.0 - (distance / (threshold + 1)))
        rows.append(
            {
                "photo_a": representative["filename"],
                "photo_b": photo["filename"],
                "content_hash": f"visual-dhash:{representative['visualHash']}",
                "confidence": f"{confidence:.3f}",
            }
        )
    return rows


def find_duplicates(
    photos: List[Dict[str, Any]],
    dedupe_mode: str,
    threshold: int,
) -> List[Dict[str, Any]]:
    """Find duplicate candidates using the configured archive dedupe mode."""
    if dedupe_mode == "visual-dhash":
        return find_visual_duplicates(photos, threshold)
    return find_exact_duplicates(photos)


def duplicate_candidates_csv(rows: List[Dict[str, Any]]) -> str:
    """Render duplicate candidates as CSV with the required headers."""
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["photo_a", "photo_b", "content_hash", "confidence"],
    )
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return output.getvalue()


def slug(value: str) -> str:
    """Create a readable folder slug from an event label."""
    chars: List[str] = []
    for char in value.lower():
        if char.isalnum():
            chars.append(char)
        elif char in {" ", "-", "_"}:
            chars.append("-")
    slugged = "".join(chars)
    while "--" in slugged:
        slugged = slugged.replace("--", "-")
    return slugged.strip("-")


def accept_response_envelope(
    envelope: Dict[str, Any],
    event_log: EventLog,
    state_machine: StateMachine,
    public_keys: Dict[str, Ed25519PublicKey],
    nonces: NonceTracker,
) -> None:
    """Requester-side validation, state transition, and transcript append."""
    verify_envelope(
        envelope,
        event_log.current_root,
        REQUESTER_DID,
        public_keys,
        nonces,
    )
    state_machine.validate(envelope["verb"], envelope["body"])
    event_log.append(envelope)
    state_machine.apply(envelope["verb"], envelope["body"])


def run_demo(dataset_name: str = "mock", dataset_limit: int = 10) -> Dict[str, Any]:
    """Run the full local ATP transaction and return verification results."""
    reset_run_dir()
    requester = AgentIdentity.create(REQUESTER_DID)
    worker = AgentIdentity.create(WORKER_DID)
    public_keys = {
        requester.did: requester.public_key,
        worker.did: worker.public_key,
    }
    write_public_keys(requester, worker, RUN_DIR / "public-keys.json")
    nonces = NonceTracker()
    event_log = EventLog(RUN_DIR / "transcript.jsonl", RUN_DIR / "envelopes.jsonl")
    state_machine = StateMachine()
    if dataset_name == "nasa-artemis":
        photo_dir = create_nasa_artemis_photo_library(dataset_limit)
    else:
        photo_dir = create_mock_photo_library()
    original_hashes_before = original_photo_hashes(photo_dir)
    port = find_worker_port()
    context = WorkerContext(
        worker=worker,
        requester=requester,
        event_log=event_log,
        state_machine=state_machine,
        nonces=nonces,
        public_keys=public_keys,
        access_log_path=RUN_DIR / "lease-access-log.jsonl",
        photo_dir=photo_dir,
        artifact_dir=ARTIFACTS_DIR,
        port=port,
    )
    server, thread = start_worker_server(context)
    try:
        endpoint = f"http://127.0.0.1:{port}/atp"
        signed_card = get_json(f"http://127.0.0.1:{port}/.well-known/atp.json")
        verify_capability_card(signed_card, worker.public_key)
        write_json(RUN_DIR / "capability-card.json", signed_card)

        intent = build_intent(dataset_name)
        discover = make_envelope(
            issuer=requester,
            audience=worker.did,
            verb="DISCOVER",
            transaction_id=TRANSACTION_ID,
            prev=event_log.current_root,
            body={
                "intent": intent,
                "capability": "photo-organization",
                "capabilityCardHash": signed_card["cardHash"],
            },
            expires_at=utc_now() + timedelta(hours=1),
        )
        discover_response = post_json(endpoint, discover)
        response_card = discover_response["capabilityCard"]
        verify_capability_card(response_card, worker.public_key)
        if response_card["cardHash"] != signed_card["cardHash"]:
            raise ValueError("DISCOVER response capability card hash mismatch")
        if "photo-organization" not in response_card["card"]["capabilities"]:
            raise ValueError("worker does not advertise photo-organization")

        offer_body = build_offer_body()
        offer = make_envelope(
            issuer=requester,
            audience=worker.did,
            verb="NEGOTIATE",
            transaction_id=TRANSACTION_ID,
            prev=event_log.current_root,
            body=offer_body,
            expires_at=utc_now() + timedelta(hours=1),
        )
        negotiate_response = post_json(endpoint, offer)
        accept_envelope = negotiate_response["envelope"]
        accept_response_envelope(
            accept_envelope,
            event_log,
            state_machine,
            public_keys,
            nonces,
        )
        accept_body = accept_envelope["body"]
        if accept_body["contractHash"] != sha256_json(offer_body):
            raise ValueError("worker accept did not commit to offer hash")

        final_contract = {"offer": offer_body, "accept": accept_body}
        final_contract_hash = sha256_json(final_contract)
        write_json(RUN_DIR / "contract.json", final_contract)

        leases = build_leases(requester, photo_dir, ARTIFACTS_DIR)
        write_json(RUN_DIR / "leases.json", leases)
        route_body = {
            "intent": intent,
            "contractHash": final_contract_hash,
            "leases": leases,
            "workSession": {
                "stagingDirectory": str(ARTIFACTS_DIR.resolve()),
                "artifactDirectory": str(ARTIFACTS_DIR.resolve()),
            },
        }
        route = make_envelope(
            issuer=requester,
            audience=worker.did,
            verb="ROUTE",
            transaction_id=TRANSACTION_ID,
            prev=event_log.current_root,
            body=route_body,
            expires_at=utc_now() + timedelta(hours=1),
        )
        route_response = post_json(endpoint, route)
        settle_envelope = route_response["envelope"]
        accept_response_envelope(
            settle_envelope,
            event_log,
            state_machine,
            public_keys,
            nonces,
        )

        original_files_unchanged = originals_unchanged(original_hashes_before, photo_dir)
        attest_envelope = context.build_attest_envelope(
            originals_modified=not original_files_unchanged
        )
        receipt = attest_envelope["body"]
        accept_response_envelope(
            attest_envelope,
            event_log,
            state_machine,
            public_keys,
            nonces,
        )
        write_json(RUN_DIR / "receipt.json", receipt)

        verification = offline_verify(RUN_DIR)
        if not original_files_unchanged:
            raise ValueError("original photo files changed")
        verification["originalFilesUnchanged"] = (
            verification["originalFilesUnchanged"] and original_files_unchanged
        )
        if not verification["originalFilesUnchanged"]:
            raise ValueError("original photo file verification failed")
        write_json(RUN_DIR / "verification.json", verification)
        return verification
    finally:
        stop_worker_server(server, thread)


# ---------------------------------------------------------------------------
# 9. Verification
# ---------------------------------------------------------------------------


def expected_audience_for_envelope(envelope: Dict[str, Any]) -> str:
    """Infer the expected ATP audience for the persisted demo flow."""
    issuer = envelope["issuer"]
    verb = envelope["verb"]
    body_type = envelope["body"].get("type")
    if issuer == REQUESTER_DID and verb in {"DISCOVER", "ROUTE"}:
        return WORKER_DID
    if issuer == REQUESTER_DID and verb == "NEGOTIATE" and body_type == "offer":
        return WORKER_DID
    if issuer == WORKER_DID and verb in {"SETTLE", "ATTEST"}:
        return REQUESTER_DID
    if issuer == WORKER_DID and verb == "NEGOTIATE" and body_type == "accept":
        return REQUESTER_DID
    raise ValueError(f"cannot infer audience for {issuer} {verb}")


def verify_envelope_and_event_files(
    envelopes: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
    public_keys: Dict[str, Ed25519PublicKey],
    receipt: Dict[str, Any],
) -> Tuple[bool, bool, str]:
    """Verify persisted envelopes, transcript events, and SETTLE-root binding."""
    if len(envelopes) != len(events):
        raise ValueError("envelopes.jsonl and transcript.jsonl counts differ")
    if len(envelopes) != 6:
        raise ValueError(f"expected 6 ATP envelopes, got {len(envelopes)}")
    expected_verbs = ["DISCOVER", "NEGOTIATE", "NEGOTIATE", "ROUTE", "SETTLE", "ATTEST"]
    observed_verbs = [envelope["verb"] for envelope in envelopes]
    if observed_verbs != expected_verbs:
        raise ValueError(f"unexpected ATP verb sequence: {observed_verbs}")

    nonces = NonceTracker()
    previous = GENESIS_HASH
    settle_root: Optional[str] = None
    for index, (envelope, event) in enumerate(zip(envelopes, events)):
        verify_envelope(
            envelope=envelope,
            expected_prev=previous,
            expected_audience=expected_audience_for_envelope(envelope),
            public_keys=public_keys,
            nonces=nonces,
            check_expiry=False,
        )
        proof = envelope["proofs"][0]
        expected_body_hash = sha256_json(envelope["body"])
        expected_event_hash = EventLog.compute_event_hash(
            envelope["prev"],
            envelope["verb"],
            envelope["issuer"],
            expected_body_hash,
            envelope["createdAt"],
            envelope["nonce"],
        )
        expected_event = {
            "verb": envelope["verb"],
            "actor": envelope["issuer"],
            "prev": envelope["prev"],
            "bodyHash": expected_body_hash,
            "time": envelope["createdAt"],
            "nonce": envelope["nonce"],
            "sig": proof["signature"],
            "eventHash": expected_event_hash,
        }
        if event != expected_event:
            raise ValueError(f"transcript event {index} does not match envelope")
        if envelope["verb"] == "SETTLE":
            settle_root = expected_event_hash
        previous = expected_event_hash

    if settle_root is None:
        raise ValueError("SETTLE event missing")
    if receipt["eventRoot"] != settle_root:
        raise ValueError("receipt eventRoot does not match SETTLE event root")
    # ATP v0.3 demo rule: ATTEST contains the receipt and its prev is the SETTLE root.
    if envelopes[-1]["prev"] != receipt["eventRoot"]:
        raise ValueError("ATTEST prev must equal receipt eventRoot")
    if envelopes[-1]["body"] != receipt:
        raise ValueError("ATTEST envelope body does not match receipt.json")
    return True, True, settle_root


def verify_artifacts_from_receipt(
    receipt: Dict[str, Any],
    artifact_dir: Path,
) -> Tuple[bool, bool]:
    """Verify artifact presence and content hashes from the receipt alone."""
    artifacts = receipt["changed"]["artifacts"]
    required_paths = {"manifest.json", "album-plan.json", "duplicate-candidates.csv"}
    observed_paths = {artifact["path"] for artifact in artifacts}
    if observed_paths != required_paths:
        raise ValueError(f"receipt artifact paths mismatch: {observed_paths}")
    for artifact in artifacts:
        path = artifact_dir / artifact["path"]
        if not path.is_file():
            raise ValueError(f"missing artifact: {artifact['path']}")
        data = path.read_bytes()
        if sha256_bytes(data) != artifact["sha256"]:
            raise ValueError(f"artifact hash mismatch: {artifact['path']}")
        if len(data) != artifact["sizeBytes"]:
            raise ValueError(f"artifact size mismatch: {artifact['path']}")
    return True, True


def verify_lease_access_log(path: Path, receipt: Dict[str, Any]) -> Tuple[bool, bool, bool]:
    """Verify denied write evidence and infer original immutability from the audit log."""
    entries = read_jsonl(path)
    if not entries:
        raise ValueError("lease access log is empty")
    denied = [entry for entry in entries if not entry["allowed"]]
    denied_write_attempt_observed = any(
        entry["operation"] == "write"
        and entry["path"].endswith("illegal-worker-write.txt")
        for entry in denied
    )
    unexpected_denials = [
        entry for entry in denied if not entry["path"].endswith("illegal-worker-write.txt")
    ]
    legitimate_reads = any(
        entry["operation"] == "read" and entry["allowed"] for entry in entries
    )
    legitimate_writes = any(
        entry["operation"] == "write" and entry["allowed"] for entry in entries
    )
    originals_unmodified_claim = receipt["changed"]["originalsModified"] is False
    original_files_unchanged = originals_unmodified_claim and denied_write_attempt_observed
    lease_guard_passed = (
        denied_write_attempt_observed
        and not unexpected_denials
        and legitimate_reads
        and legitimate_writes
        and original_files_unchanged
    )
    return lease_guard_passed, original_files_unchanged, denied_write_attempt_observed


def offline_verify(run_dir: Path) -> Dict[str, Any]:
    """Verify a completed ATP run using only files in its artifact tree."""
    public_keys = load_public_keys(run_dir / "public-keys.json")
    if set(public_keys) != {REQUESTER_DID, WORKER_DID}:
        raise ValueError("public-keys.json does not contain the expected agents")
    signed_card = load_json(run_dir / "capability-card.json")
    envelopes = read_jsonl(run_dir / "envelopes.jsonl")
    events = read_jsonl(run_dir / "transcript.jsonl")
    receipt = load_json(run_dir / "receipt.json")
    leases = load_json(run_dir / "leases.json")
    contract = load_json(run_dir / "contract.json")

    capability_card_valid = verify_capability_card(
        signed_card,
        public_keys[WORKER_DID],
    )
    if envelopes[0]["body"].get("capabilityCardHash") != signed_card["cardHash"]:
        raise ValueError("DISCOVER does not commit to capability card hash")
    verify_leases(leases, public_keys[REQUESTER_DID], check_ttl=False)
    if contract != {"offer": envelopes[1]["body"], "accept": envelopes[2]["body"]}:
        raise ValueError("contract.json does not match NEGOTIATE envelopes")
    if envelopes[2]["body"]["contractHash"] != sha256_json(envelopes[1]["body"]):
        raise ValueError("NEGOTIATE accept does not commit to offer hash")
    if envelopes[3]["body"]["contractHash"] != sha256_json(contract):
        raise ValueError("ROUTE does not commit to final contract hash")
    if envelopes[3]["body"]["leases"] != leases:
        raise ValueError("leases.json does not match ROUTE leases")
    receipt_signature_valid = verify_receipt(receipt, public_keys[WORKER_DID])
    envelope_signatures_valid, event_chain_valid, event_root = (
        verify_envelope_and_event_files(envelopes, events, public_keys, receipt)
    )
    artifact_files_present, artifact_hashes_valid = verify_artifacts_from_receipt(
        receipt,
        run_dir / "artifacts",
    )
    lease_guard_passed, original_files_unchanged, denied_write_attempt_observed = (
        verify_lease_access_log(run_dir / "lease-access-log.jsonl", receipt)
    )
    offline_verification_valid = all(
        [
            receipt_signature_valid,
            event_chain_valid,
            lease_guard_passed,
            original_files_unchanged,
            denied_write_attempt_observed,
            artifact_files_present,
            artifact_hashes_valid,
            capability_card_valid,
            envelope_signatures_valid,
        ]
    )
    if not offline_verification_valid:
        raise ValueError("offline verification failed")
    return {
        "receiptSignatureValid": receipt_signature_valid,
        "eventChainValid": event_chain_valid,
        "leaseGuardPassed": lease_guard_passed,
        "originalFilesUnchanged": original_files_unchanged,
        "deniedWriteAttemptObserved": denied_write_attempt_observed,
        "artifactFilesPresent": artifact_files_present,
        "artifactHashesValid": artifact_hashes_valid,
        "capabilityCardValid": capability_card_valid,
        "envelopeSignaturesValid": envelope_signatures_valid,
        "offlineVerificationValid": offline_verification_valid,
        "receiptHash": receipt["receiptHash"],
        "eventRoot": event_root,
    }


def main() -> None:
    """Execute or offline-verify the ATP local demo."""
    if len(sys.argv) == 3 and sys.argv[1] == "verify":
        run_dir = Path(sys.argv[2])
        receipt = load_json(run_dir / "receipt.json")
        configure_transaction(receipt["transactionId"])
        verification = offline_verify(run_dir)
        if not verification["offlineVerificationValid"]:
            raise ValueError("offline verification failed")
        print("Offline verification valid: True")
        return
    if len(sys.argv) in {2, 4} and sys.argv[1] == "receipt-zero":
        limit = 100
        if len(sys.argv) == 4:
            if sys.argv[2] != "--limit":
                raise SystemExit(
                    "usage: python atp_demo.py receipt-zero [--limit N]"
                )
            limit = int(sys.argv[3])
        configure_transaction("receipt_zero_001")
        verification = run_demo(dataset_name="nasa-artemis", dataset_limit=limit)
        receipt_valid = bool(verification["receiptSignatureValid"])
        print(f"Receipt Zero complete: {RUN_DIR.as_posix()}/")
        print(f"Receipt hash: {verification['receiptHash']}")
        print(f"Receipt valid: {receipt_valid}")
        print(f"Event chain valid: {verification['eventChainValid']}")
        print(f"Lease guard passed: {verification['leaseGuardPassed']}")
        print(f"Original files unchanged: {verification['originalFilesUnchanged']}")
        print(f"Offline verification valid: {verification['offlineVerificationValid']}")
        return
    if len(sys.argv) != 1:
        raise SystemExit(
            "usage: python atp_demo.py "
            "[verify runs/atp_photo_001] "
            "[receipt-zero --limit N]"
        )

    verification = run_demo()
    receipt_valid = bool(verification["receiptSignatureValid"])
    print(f"ATP transaction complete: {RUN_DIR.as_posix()}/")
    print(f"Receipt hash: {verification['receiptHash']}")
    print(f"Receipt valid: {receipt_valid}")
    print(f"Event chain valid: {verification['eventChainValid']}")
    print(f"Lease guard passed: {verification['leaseGuardPassed']}")
    print(f"Original files unchanged: {verification['originalFilesUnchanged']}")
    print(f"Offline verification valid: {verification['offlineVerificationValid']}")


if __name__ == "__main__":
    main()
