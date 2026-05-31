import json
import subprocess
import sys
from pathlib import Path
from pydantic import BaseModel


class SignerConfig(BaseModel):
    id: str
    full_name: str
    nickname: str
    tokens: list[str]


class PKIConfig(BaseModel):
    rfc3161_url: str
    signer_cert: Path
    signer_key: Path
    ca_chain: Path | None = None
    root_ca: Path


class AppConfig(BaseModel):
    signers: list[SignerConfig]
    viewer_tokens: list[str]
    readme_pages: list[Path]
    pki: PKIConfig


def load_config(path: Path) -> AppConfig:
    config_dir = path.parent.resolve()
    with open(path) as f:
        data = json.load(f)

    for key in ("readme_pages",):
        if key in data:
            resolved = []
            for p in data[key]:
                pp = Path(p)
                if not pp.is_absolute():
                    pp = config_dir / pp
                resolved.append(str(pp.resolve()))
            data[key] = resolved

    if "pki" in data:
        for key in ("signer_cert", "signer_key", "root_ca"):
            if key in data["pki"]:
                pp = Path(data["pki"][key])
                if not pp.is_absolute():
                    data["pki"][key] = str((config_dir / pp).resolve())
        if "ca_chain" in data["pki"] and data["pki"]["ca_chain"]:
            pp = Path(data["pki"]["ca_chain"])
            if not pp.is_absolute():
                data["pki"]["ca_chain"] = str((config_dir / pp).resolve())

    return AppConfig(**data)


def _run_openssl(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(["openssl"] + args, capture_output=True, text=True)


def verify_cert_chain(pki: PKIConfig) -> None:
    cmd = ["verify"]
    if pki.ca_chain:
        cmd += ["-untrusted", str(pki.ca_chain)]
    cmd += ["-CAfile", str(pki.root_ca), str(pki.signer_cert)]

    result = _run_openssl(cmd)
    if result.returncode != 0:
        print(f"ERROR: Certificate verification failed: {result.stderr.strip()}")
        sys.exit(1)
    print("Certificate chain: OK")

    cn = _run_openssl([
        "x509", "-in", str(pki.signer_cert), "-noout", "-subject"
    ])
    if cn.returncode == 0:
        print(f"Signer certificate subject: {cn.stdout.strip()}")

    cert_pub = _run_openssl([
        "x509", "-in", str(pki.signer_cert), "-noout", "-pubkey"
    ])
    key_pub = _run_openssl([
        "pkey", "-in", str(pki.signer_key), "-pubout"
    ])
    if cert_pub.stdout.strip() != key_pub.stdout.strip():
        print("ERROR: Private key does not match certificate public key")
        sys.exit(1)
    print("Key matches certificate: OK")


def check_cert_valid(pki: PKIConfig) -> bool:
    cmd = ["verify"]
    if pki.ca_chain:
        cmd += ["-untrusted", str(pki.ca_chain)]
    cmd += ["-CAfile", str(pki.root_ca), str(pki.signer_cert)]
    result = _run_openssl(cmd)
    return result.returncode == 0
