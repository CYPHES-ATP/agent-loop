# ATP Profile For ERC-8004 Agents

This document defines how an ATP receipt can be referenced by ERC-8004 agent identity, reputation, and validation flows.

ERC-8004 defines on-chain registries for agent identity, reputation, and validation. ATP defines an off-chain transaction envelope and receipt bundle for agent-to-agent work.

## Source Standards

ERC-8004:

```text
https://eips.ethereum.org/EIPS/eip-8004
```

ATP whitepaper:

```text
https://cyphes.com/ATP.pdf
```

## Scope

This profile does not replace ERC-8004.

This profile specifies how an ATP transaction bundle can be used as:

- an ERC-8004 agent service endpoint
- an ERC-8004 reputation feedback artifact
- an ERC-8004 validation request artifact
- an ERC-8004 validation response artifact

## Agent Registration File

An ERC-8004 registration file MAY advertise ATP support as a service:

```json
{
  "type": "https://eips.ethereum.org/EIPS/eip-8004#registration-v1",
  "name": "cyphes-receipt-zero-worker",
  "description": "ATP worker agent capable of signed receipt-producing transactions.",
  "image": "https://atp.cyphes.io/assets/agent.png",
  "services": [
    {
      "name": "ATP",
      "endpoint": "https://atp.cyphes.io/.well-known/atp.json",
      "version": "0.3"
    }
  ],
  "active": true,
  "registrations": [
    {
      "agentId": 0,
      "agentRegistry": "eip155:<chainId>:<identityRegistry>"
    }
  ],
  "supportedTrust": [
    "reputation",
    "validation"
  ]
}
```

The ATP capability card remains an ATP object and is served at:

```text
/.well-known/atp.json
```

## ATP Receipt Bundle

An ATP receipt bundle is a directory containing:

```text
public-keys.json
capability-card.json
envelopes.jsonl
transcript.jsonl
contract.json
leases.json
lease-access-log.jsonl
verification.json
artifacts/
receipt.json
```

The canonical receipt commitment is:

```text
receipt.receiptHash
```

The event-chain commitment is:

```text
receipt.eventRoot
```

## ERC-8004 Validation Request

An ERC-8004 validation request can point to the ATP receipt bundle.

Recommended off-chain request payload:

```json
{
  "type": "https://cyphes.com/atp/erc-8004-validation-request-v1",
  "atp": "0.3",
  "receiptUri": "https://atp.cyphes.io/receipts/1/",
  "receiptHash": "sha256:<receipt-hash>",
  "eventRoot": "sha256:<event-root>",
  "offlineVerify": "python3 atp_demo.py verify runs/receipt_zero_001",
  "sourceCommit": "<git-commit>",
  "dataset": {
    "name": "NASA Artemis II public image archive",
    "source": "https://eol.jsc.nasa.gov/SearchPhotos/ShowQueryResults-TextTable.pl?results=Artemis_Artemis2_all"
  }
}
```

For the ERC-8004 `validationRequest` call:

```text
requestURI = URI of the request payload
requestHash = keccak256(canonical request payload)
```

The request payload SHOULD also contain the ATP `receiptHash`, which is SHA-256 over the canonical receipt body as defined by ATP.

## ERC-8004 Validation Response

A validator can respond with an off-chain validation artifact:

```json
{
  "type": "https://cyphes.com/atp/erc-8004-validation-response-v1",
  "atp": "0.3",
  "receiptUri": "https://atp.cyphes.io/receipts/1/",
  "receiptHash": "sha256:<receipt-hash>",
  "eventRoot": "sha256:<event-root>",
  "result": "valid",
  "checks": {
    "receiptSignatureValid": true,
    "eventChainValid": true,
    "leaseGuardPassed": true,
    "originalFilesUnchanged": true,
    "artifactHashesValid": true,
    "capabilityCardValid": true,
    "envelopeSignaturesValid": true,
    "offlineVerificationValid": true
  }
}
```

For the ERC-8004 `validationResponse` call:

```text
response = 100
responseURI = URI of the validation response artifact
responseHash = keccak256(canonical validation response artifact)
tag = "atp-receipt"
```

## ERC-8004 Reputation Feedback

ATP receipts can also be referenced by ERC-8004 feedback.

Recommended tags:

```text
tag1 = "atp-receipt"
tag2 = "completed"
```

Recommended off-chain feedback payload:

```json
{
  "type": "https://cyphes.com/atp/erc-8004-feedback-v1",
  "atp": "0.3",
  "receiptUri": "https://atp.cyphes.io/receipts/1/",
  "receiptHash": "sha256:<receipt-hash>",
  "eventRoot": "sha256:<event-root>",
  "clientAgent": {
    "did": "did:example:agent:requester-7",
    "erc8004": {
      "agentRegistry": "eip155:<chainId>:<identityRegistry>",
      "agentId": "<requester-agent-id>"
    }
  },
  "workerAgent": {
    "did": "did:example:agent:worker-42",
    "erc8004": {
      "agentRegistry": "eip155:<chainId>:<identityRegistry>",
      "agentId": "<worker-agent-id>"
    }
  },
  "result": "completed"
}
```

## Anchor Payload

The public Receipt Zero anchor SHOULD commit to:

```json
{
  "type": "https://cyphes.com/atp/receipt-anchor-v1",
  "receiptUri": "https://atp.cyphes.io/receipts/1/",
  "receiptHash": "sha256:<receipt-hash>",
  "eventRoot": "sha256:<event-root>",
  "artifactTreeUri": "ipfs://<cid>",
  "sourceCommit": "<git-commit>"
}
```

For Ethereum calldata, encode the canonical anchor payload or its hash. For ERC-8004 registry calls, use the ERC-8004-required `keccak256` commitment to the off-chain payload.

## Verification Rule

An ATP receipt referenced by ERC-8004 is valid only if:

1. The ATP offline verifier succeeds.
2. The receipt hash in the ERC-8004 payload matches `receipt.json`.
3. The event root in the ERC-8004 payload matches `receipt.eventRoot`.
4. The URI referenced by ERC-8004 resolves to the same receipt bundle.
5. Any `keccak256` request or response hash matches the ERC-8004 off-chain payload.
