# Receipt Zero

Receipt Zero is the first public ATP receipt run intended for permanent publication.

It uses the same ATP transaction loop as `atp_demo.py`, but points the work at a public NASA Artemis II image dataset instead of the local mock photo set.

## Dataset

Source:

```text
https://eol.jsc.nasa.gov/SearchPhotos/ShowQueryResults-TextTable.pl?results=Artemis_Artemis2_all
```

Image source pattern:

```text
https://eol.jsc.nasa.gov/DatabaseImages/ESC/small/ART002/<PHOTO_ID>.JPG
```

The NASA Gateway result page reports 11,364 Artemis II images. The current command accepts a `--limit` value so the run can be rehearsed on a small subset before the public canonical run.

## Run

Install dependencies:

```bash
python3 -m pip install cryptography fastapi uvicorn
```

Run a rehearsal:

```bash
python3 atp_demo.py receipt-zero --limit 100
```

Run the public candidate:

```bash
python3 atp_demo.py receipt-zero --limit 11364
```

This creates:

```text
runs/receipt_zero_001/
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

## Verify

Verify from files only:

```bash
python3 atp_demo.py verify runs/receipt_zero_001
```

Expected output:

```text
Offline verification valid: True
```

## Publish Checklist

Before publication:

1. Run `python3 atp_demo.py receipt-zero --limit 11364`.
2. Run `python3 atp_demo.py verify runs/receipt_zero_001`.
3. Record:
   - `receiptHash`
   - `eventRoot`
   - source Git commit
   - dataset URL
   - artifact tree hash or IPFS CID
4. Upload the full `runs/receipt_zero_001/` artifact tree to permanent storage.
5. Publish a readable receipt page that links to every file in the artifact tree.
6. Anchor the receipt hash using OpenTimestamps, Ethereum calldata, or both.
7. Publish the ERC-8004 ATP profile document beside the receipt.

The repository includes a static viewer template:

```text
site/receipt-zero.html
```

For static hosting, place the viewer beside the run files, or serve it with:

```text
?base=https://atp.cyphes.io/receipts/1/
```

## Publication Targets

Preferred URLs:

```text
https://receipt.cyphes.io/zero
https://atp.cyphes.io/receipts/1
https://atp.cyphes.io/spec/erc-8004-atp-profile
```

## Non-Goals

Receipt Zero does not claim visual near-duplicate detection. The current run detects exact duplicate candidates by identical SHA-256 content hash.

Receipt Zero does not require trusting the worker, requester, hosting provider, or live server state. The offline verifier uses the persisted public keys, signed envelopes, event log, receipt, artifacts, and lease log.
