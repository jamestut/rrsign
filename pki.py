import subprocess
import requests
import tempfile
from pathlib import Path
from config import PKIConfig


def cms_sign(data: bytes, pki: PKIConfig) -> bytes:
    with tempfile.NamedTemporaryFile(suffix=".dat", delete=False) as f:
        f.write(data)
        infile = f.name

    outfile = infile + ".sig"

    try:
        cmd = [
            "openssl", "cms", "-sign", "-binary",
            "-in", infile, "-md", "sha512",
            "-signer", str(pki.signer_cert),
            "-inkey", str(pki.signer_key),
            "-out", outfile, "-outform", "der",
        ]
        if pki.ca_chain:
            cmd += ["-certfile", str(pki.ca_chain)]

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"CMS signing failed: {result.stderr}")

        with open(outfile, "rb") as f:
            return f.read()
    finally:
        Path(infile).unlink(missing_ok=True)
        Path(outfile).unlink(missing_ok=True)


def rfc3161_timestamp(data: bytes, url: str) -> bytes:
    with tempfile.NamedTemporaryFile(suffix=".dat", delete=False) as f:
        f.write(data)
        infile = f.name

    tsq_file = infile + ".tsq"
    tsr_file = infile + ".tsr"

    try:
        subprocess.run(
            ["openssl", "ts", "-query", "-data", infile,
             "-cert", "-sha512", "-out", tsq_file],
            capture_output=True, check=True,
        )

        with open(tsq_file, "rb") as f:
            tsq_data = f.read()

        resp = requests.post(
            url,
            data=tsq_data,
            headers={"Content-Type": "application/timestamp-query"},
            timeout=30,
        )
        resp.raise_for_status()

        with open(tsr_file, "wb") as f:
            f.write(resp.content)

        with open(tsr_file, "rb") as f:
            return f.read()
    finally:
        for p in (infile, tsq_file, tsr_file):
            Path(p).unlink(missing_ok=True)

