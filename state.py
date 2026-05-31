import json
import fcntl
from pathlib import Path

DEFAULT_SIGNER = {
    "agreed_pages": [],
    "rejected": False,
    "final_agreed": False,
    "final_agreed_at": None,
    "ip": None,
    "ipv6": None,
    "user_agent": None,
    "geolocation": None,
}


def init_state(workdir: Path) -> None:
    path = workdir / "state.json"
    if not path.exists():
        _write(path, {"proof_generated": False, "signers": {}})


def read_state(workdir: Path) -> dict:
    path = workdir / "state.json"
    with open(path) as f:
        return json.load(f)


def _write(path: Path, state: dict) -> None:
    with open(path, "w") as f:
        json.dump(state, f, indent=2)


def lock_state(workdir: Path):
    path = workdir / "state.json"
    f = open(path, "r+")
    fcntl.flock(f, fcntl.LOCK_EX)
    return f


def unlock_state(f) -> None:
    fcntl.flock(f, fcntl.LOCK_UN)
    f.close()


def ensure_signer(state: dict, signer_id: str) -> dict:
    return state.setdefault("signers", {}).setdefault(
        signer_id, dict(DEFAULT_SIGNER)
    )
