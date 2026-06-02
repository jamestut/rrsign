import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from config import AppConfig
from pki import cms_sign, rfc3161_timestamp


def generate_proof(
    state: dict,
    config: AppConfig,
    pages: list[str],
    workdir: Path,
) -> Path:
    agreed_parties = []
    for signer in config.signers:
        s = state.get("signers", {}).get(signer.id, {})
        if s.get("final_agreed"):
            agreed_parties.append({
                "id": signer.id,
                "full_name": signer.full_name,
                "agreed_at": s.get("final_agreed_at"),
                "ip": s.get("ip"),
                "user_agent": s.get("user_agent"),
                "geolocation": s.get("geolocation"),
            })

    now = datetime.now(timezone.utc)
    agreement = {
        "pages": pages,
        "time": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "agreed_parties": agreed_parties,
    }

    agreement_bytes = json.dumps(agreement, indent=2).encode("utf-8")
    signature_der = cms_sign(agreement_bytes, config.pki)
    timestamp_der = rfc3161_timestamp(signature_der, config.pki.rfc3161_url)

    ts_str = now.strftime("%Y%m%d_%H%M%S")
    zip_path = workdir / f"proof_{ts_str}.zip"

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("agreement.json", agreement_bytes)
        zf.writestr("signature.der", signature_der)
        zf.writestr("timestamp.der", timestamp_der)
        zf.writestr("README.md", (Path(__file__).parent / "assets" / "VERIFICATION_README.md").read_text())

    return zip_path
