# CYPHES ATP Demo

Agent Transfer Protocol (ATP) is a proposed protocol for auditable agent-to-agent work. It gives agents a transaction loop for discovering capabilities, negotiating scope, routing work with signed context leases, settling value, and producing a verifiable Proof of Cognition receipt.

This repository contains the first local ATP demonstration script: a single-file Python MVP that runs the full ATP loop between two locally hosted agents and emits a self-contained proof bundle that can be verified later from files alone.

## Status

This is a local protocol MVP.

- One script: `atp_demo.py`
- One command to run the demo
- One artifact tree per run
- Local HTTP only
- No P2P
- No forks
- No external agent frameworks
- No real payment rails

The purpose is to make the ATP loop inspectable, reproducible, and understandable before expanding into a full node.

## What The Demo Shows

The demo models a photo-library organization task.

Two local agents participate:

- Requester: `did:example:agent:requester-7`
- Worker: `did:example:agent:worker-42`

The requester asks the worker to organize a mock photo library into dated event albums. The worker receives signed leases, reads only the leased photo directory, writes only to a leased staging directory, detects duplicate content hashes, creates artifacts, settles a zero-value transaction, and returns a signed Proof of Cognition receipt.

The demo proves:

- who participated
- what capability was advertised
- what was requested
- what contract was accepted
- what leases were granted
- what files were accessed
- what access was denied
- what artifacts were produced
- that artifact contents match the receipt
- that original files were not modified
- what settlement occurred
- that the event chain and signatures verify offline

## Protocol Flow

```text
REQUESTER agent_a              WORKER agent_b

DISCOVER  --------------------> signed capability discovery
NEGOTIATE --------------------> contract offer
NEGOTIATE <-------------------- contract accept
ROUTE     --------------------> intent + signed leases + sandbox references
SETTLE    <-------------------- zero-value settlement record
ATTEST    <-------------------- Proof of Cognition receipt
```

The demo uses the ATP v0.3 envelope verbs:

- `DISCOVER`
- `NEGOTIATE`
- `ROUTE`
- `SETTLE`
- `ATTEST`

Every accepted protocol message is signed with Ed25519, appended to the event log, and persisted as a full envelope.

## Quickstart

Install the required dependencies:

```bash
python3 -m pip install cryptography fastapi uvicorn
```

Run the demo:

```bash
python3 atp_demo.py
```

If your environment maps `python` to Python 3, this also works:

```bash
python atp_demo.py
```

Expected output:

```text
ATP transaction complete: runs/atp_photo_001/
Receipt hash: <hash>
Receipt valid: True
Event chain valid: True
Lease guard passed: True
Original files unchanged: True
Offline verification valid: True
```

Verify a completed run from files only:

```bash
python3 atp_demo.py verify runs/atp_photo_001
```

Expected output:

```text
Offline verification valid: True
```

## Generated Proof Bundle

Each run removes and recreates:

```text
runs/atp_photo_001/
├── public-keys.json
├── capability-card.json
├── envelopes.jsonl
├── transcript.jsonl
├── contract.json
├── leases.json
├── lease-access-log.jsonl
├── verification.json
├── artifacts/
│   ├── manifest.json
│   ├── album-plan.json
│   └── duplicate-candidates.csv
└── receipt.json
```

The generated `runs/` directory is local evidence and is intentionally not committed to the repository.

## How To Audit A Run

Start with:

- `runs/atp_photo_001/receipt.json`
- `runs/atp_photo_001/verification.json`

Then inspect the supporting evidence:

- `public-keys.json`: persisted Ed25519 public keys for the requester and worker
- `capability-card.json`: signed worker capability card and card hash
- `envelopes.jsonl`: full signed ATP envelopes in transaction order
- `transcript.jsonl`: compact event log with event hashes
- `contract.json`: final negotiated offer and accept
- `leases.json`: requester-signed read and write leases
- `lease-access-log.jsonl`: every allowed or denied lease-guard access attempt
- `artifacts/manifest.json`: staged work manifest
- `artifacts/album-plan.json`: proposed event album structure
- `artifacts/duplicate-candidates.csv`: duplicate photo candidates by content hash

The offline verifier checks:

- public key import
- signed capability card
- envelope signatures
- expected envelope audience
- nonce uniqueness
- event hash chain
- SETTLE-before-ATTEST receipt binding
- receipt signature
- receipt hash
- artifact hashes and sizes
- denied illegal write attempt
- absence of unexpected denied access attempts
- original-file immutability claim

## Proof Of Cognition

The receipt is the main human-readable audit object.

It records:

- the requested intent
- constraints and success condition
- leases and accessed resources
- produced artifacts with content hashes
- the claim that originals were not modified
- simulated owner approval
- zero-value settlement details
- event root binding
- worker signature

In this demo, `receipt.eventRoot` equals the transcript root after `SETTLE` and before `ATTEST`. The `ATTEST` envelope then carries the signed receipt and uses that same root as its `prev` value. This makes the receipt commit to the completed transaction up to settlement, while the final event commits the receipt back into the transcript.

## Security Properties Demonstrated

This local MVP demonstrates:

- canonical JSON signing
- Ed25519 signatures
- unpadded base64url proof encoding
- signed worker capability discovery
- signed ATP envelopes
- signed context leases
- lease-scoped file reads and writes
- replay resistance through nonce tracking
- audience validation
- append-only event hashing
- content-addressed artifacts
- offline verification from persisted files

It does not claim to provide production sandboxing, remote trust resolution, decentralized routing, real settlement, or adversarial process isolation.

## Roadmap To A Full ATP Node

The next milestones are:

1. Conformance tests for invalid signatures, replayed nonces, wrong audiences, expired leases, mutated artifacts, and broken event roots.
2. A persistent ATP node with identity resolution, envelope inbox/outbox, event storage, lease storage, and receipt storage.
3. A verifier CLI that can audit many ATP runs, not only this demo fixture.
4. Stronger sandboxing and policy enforcement for real tools and filesystems.
5. Lease revocation, long-running session management, and durable audit trails.
6. Remote HTTP transport, then federated or P2P routing.
7. Real settlement adapters.
8. A human audit viewer for receipts, transcripts, envelopes, leases, and artifacts.

## Repository Contents

```text
.
├── atp_demo.py
├── README.md
└── LICENSE
```

## License

MIT License. See `LICENSE`.
