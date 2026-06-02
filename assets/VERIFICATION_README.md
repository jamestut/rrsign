# Proof of Agreement — Verification

This archive contains the cryptographic proof of agreement.

## Files

- **agreement.json** — The original agreement document and signed-party metadata.
- **signature.der** — CMS (PKCS#7) detached signature of `agreement.json` (SHA-512).
- **timestamp.der** — RFC 3161 timestamp token for `signature.der`.

## Verification Steps

### 1. Verify CMS Signature

```bash
openssl cms -verify -in signature.der -inform der -content agreement.json \
    -binary -out /dev/null -CAfile <root-ca-bundle.pem>
```

### 2. Inspect CMS Signature Details

```bash
openssl cms -cmsout -in signature.der -inform der -print
```

### 3. Verify RFC 3161 Timestamp

```bash
openssl ts -verify -data signature.der -in timestamp.der \
    -CAfile <tsa-root-ca-bundle.pem>
```

### 4. Inspect Timestamp Details

```bash
openssl ts -reply -in timestamp.der -text
```
