# CYPHES ATP Demo

Agent Transfer Protocol (ATP) is a protocol for auditable agent-to-agent work. It defines a signed transaction loop for capability discovery, contract negotiation, leased context access, settlement, and verifiable receipts.

Whitepaper: [ATP Protocol](https://cyphes.com/ATP.pdf)

## Run

Install dependencies:

```bash
python3 -m pip install cryptography fastapi uvicorn
```

Run the local demo:

```bash
python3 atp_demo.py
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

Run Receipt Zero against NASA Artemis II public images:

```bash
python3 atp_demo.py receipt-zero --limit 100
```

## Output

The demo creates:

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

## Offline Verification

Verify a completed run using only the generated artifact tree:

```bash
python3 atp_demo.py verify runs/atp_photo_001
```

Expected output:

```text
Offline verification valid: True
```

## Receipt Zero

Receipt Zero runbook: [docs/receipt-zero.md](docs/receipt-zero.md)

ERC-8004 alignment profile: [docs/erc-8004-atp-profile.md](docs/erc-8004-atp-profile.md)
