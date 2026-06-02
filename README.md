# Project RRSign

A FastAPI-based web app for digitally signing multi-party agreements with PKI-backed proof.

## Requirements

- Python 3.12+
- OpenSSL 3.x (for CMS signing and RFC 3161 timestamping)

## Quick Start

```bash
# Install dependencies
uv pip install -r requirements.txt

# Run with a config and working directory
python3 main.py --config config.json --workdir ./data
```

The server starts on port 8000 by default. Open `http://localhost:8000/#token=<your-token>` in a browser.

## Configuration

A JSON file specifying signers, viewers, README pages, and PKI settings.

```json
{
  "signers": [
    {
      "id": "alice",
      "full_name": "Alice Johnson",
      "nickname": "Alice",
      "tokens": ["token-for-alice-1", "token-for-alice-2"]
    }
  ],
  "viewer_tokens": ["token-for-viewer"],
  "readme_pages": [
    "page1.md",
    "page2.md",
    "page3.md"
  ],
  "pki": {
    "rfc3161_url": "http://timestamp.digicert.com",
    "signer_cert": "pki/signer-cert.pem",
    "signer_key": "pki/signer-key.pem",
    "ca_chain": "pki/fullchain.pem",
    "root_ca": "pki/root-ca.pem"
  }
}
```

### Fields

| Field | Required | Description |
|-------|----------|-------------|
| `signers[].id` | yes | Unique identifier for the signer |
| `signers[].full_name` | yes | Full legal name (used for final agree/reject) |
| `signers[].nickname` | yes | Nickname (used for per-page agree) |
| `signers[].tokens` | yes | List of authentication tokens |
| `viewer_tokens` | yes | List of tokens for read-only access |
| `readme_pages` | yes | Paths to Markdown files (relative to config file) |
| `pki.rfc3161_url` | yes | RFC 3161 Time-Stamp Authority URL |
| `pki.signer_cert` | yes | Path to the signing certificate (PEM) |
| `pki.signer_key` | yes | Path to the private key (PEM) |
| `pki.ca_chain` | no | Path to intermediate CA chain (PEM) |
| `pki.root_ca` | yes | Path to root CA bundle (PEM) |

All relative paths in `readme_pages` and `pki.*` are resolved relative to the config file's directory.

## CLI Arguments

```
--config PATH            Path to configuration JSON (required)
--workdir PATH           Working directory for state.json and proof zips (required)
--port INT               HTTP port (default: 8000)
--host TEXT              Bind address (default: 0.0.0.0)
--forwarded-allow-ips    Comma-separated proxy IPs trusted for X-Forwarded-For (default: 127.0.0.1; use "*" to trust all)
```

## URL Fragment Authentication

Users authenticate via the URL fragment (never sent to the server in the raw URL):

```
http://localhost:8000/#token=alice-token&page=2
```

- `token` — Authentication token from the config
- `page` — (optional) Page number to jump to (0-indexed)

The fragment is read client-side and sent as an `Authorization: Bearer <token>` header on all API calls.

## Project Structure

```
rrsign/
├── main.py              # FastAPI app, routes, CLI entry point
├── config.py            # Config model, file loader, certificate verification
├── auth.py              # Token → role/signer lookup
├── state.py             # State persistence with file locking
├── pki.py               # CMS signing, RFC 3161 timestamping
├── proof.py             # Proof-of-agreement zip generation
├── templates/
│   └── index.html       # Single-page application (580 lines)
├── requirements.txt
└── README.md
```

## State File

The working directory stores `state.json` with the signing progress:

```json
{
  "proof_generated": false,
  "signers": {
    "alice": {
      "agreed_pages": [0, 1],
      "rejected": false,
      "final_agreed": false,
      "final_agreed_at": null,
      "ip": "192.0.2.1",
      "user_agent": "Mozilla/5.0...",
      "geolocation": null
    }
  }
}
```

All state mutations use `fcntl.flock` for concurrency safety.

## Proof of Agreement

When all signers have clicked "final agree", the server automatically:

1. Builds `agreement.json` — pages, timestamp, agreed parties with IP/UA/geolocation
2. CMS-signs it: `openssl cms -sign -binary -md sha512 -signer cert.pem -inkey key.pem -outform der`
3. RFC 3161 timestamps the signature
4. Writes a verification `README.md`
5. Zips all 4 files into `proof_<timestamp>.zip`

The zip is available for download via the UI for both signers and viewers.

## Debugging

### Enable verbose logs

Start with Python's verbose mode or add `--log-level`:

```bash
python3 -u main.py --config config.json --workdir ./data
```

All server requests are logged to stdout by uvicorn.

### Test endpoints with curl

```bash
# Auth
curl -s http://localhost:8000/api/auth \
  -X POST -H 'Content-Type: application/json' \
  -d '{"token":"alice-token"}'

# Get pages
curl -s http://localhost:8000/api/pages \
  -H 'Authorization: Bearer alice-token'

# Agree to page 0
curl -s http://localhost:8000/api/page/0/agree \
  -X POST -H 'Authorization: Bearer alice-token' \
  -H 'Content-Type: application/json' \
  -d '{"name":"Alice"}'

# Check status
curl -s http://localhost:8000/api/status \
  -H 'Authorization: Bearer viewer-token'
```

### Inspect state file

```bash
cat ./data/state.json | python3 -m json.tool
```

### Verify proof manually

```bash
cd ./data
unzip proof_*.zip -d proof_extract

# Verify CMS signature
openssl cms -verify -in proof_extract/signature.der -inform der \
  -content proof_extract/agreement.json \
  -CAfile /path/to/root-ca.pem -binary -out /dev/null

# Inspect timestamp
openssl ts -reply -in proof_extract/timestamp.der -text
```

### Debug certificate chain

```bash
openssl verify -CAfile root-ca.pem -untrusted fullchain.pem signer-cert.pem
```

### Run on a different port

```bash
python3 main.py --config config.json --workdir ./data --port 9000
```

### Common issues

| Symptom | Likely cause |
|---------|--------------|
| All API routes return 404 | Port conflict (use `--port` to change) |
| "System Unavailable" at root | Signing certificate is expired or chain broken |
| "Invalid token" | Token not found in config; check URL fragment |
| Nickname not matching | Per-page agree is case-insensitive; full-name agree is case-sensitive |
| Proof not generating | Not all signers have final-agreed |
| CMS verification fails | Missing `-binary` flag or wrong CA file |
| Timestamp verification fails | TSA root CA not in your trust bundle |
