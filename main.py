#!/usr/bin/env python3
import argparse
import json
import time
import sys
from pathlib import Path
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
import uvicorn

from config import load_config, verify_cert_chain, check_cert_valid, AppConfig
from auth import build_token_map
from state import init_state, read_state, lock_state, unlock_state, ensure_signer
from proof import generate_proof

# ── Module-level globals (populated at startup) ──────────────────────
_config: AppConfig | None = None
_pages: list[str] = []
_token_map: dict = {}
_workdir: Path | None = None
_cert_cache: dict = {"valid": None, "at": 0.0, "ttl": 60}
_spa_html: str = ""

UNAVAILABLE_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>System Unavailable</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;
background:#f8f9fa;color:#333}
div{text-align:center;padding:2rem;max-width:480px}
h1{margin-bottom:.5rem}
@media(prefers-color-scheme:dark){
body{background:#0f0f1a;color:#e0e0e0}
}
</style></head><body><div>
<h1>⚠ System Unavailable</h1>
<p>The signing certificate is no longer valid or the system has a configuration issue.</p>
<p style="margin-top:1rem;color:#666">Please contact your administrator.</p>
</div></body></html>"""

# ── Lifespan ─────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Nothing to do at startup — init already done by init_app()
    yield


# ── App ──────────────────────────────────────────────────────────────
app = FastAPI(title="RRSign", lifespan=lifespan)


def get_user(request: Request) -> dict:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, detail="Missing Authorization header")
    info = _token_map.get(auth[7:])
    if not info:
        raise HTTPException(401, detail="Invalid token")
    return info


# ── Routes ───────────────────────────────────────────────────────────

@app.get("/")
async def root():
    state = read_state(_workdir)
    if not state.get("proof_generated", False):
        now = time.time()
        c = _cert_cache
        if c["valid"] is None or (now - c["at"]) > c["ttl"]:
            c["valid"] = check_cert_valid(_config.pki)
            c["at"] = now
        if not c["valid"]:
            return HTMLResponse(UNAVAILABLE_HTML, status_code=503)
    return HTMLResponse(_spa_html)


@app.post("/api/auth")
async def api_auth(request: Request):
    body = await request.json()
    token = body.get("token", "")
    info = _token_map.get(token)
    if not info:
        return JSONResponse({"role": "invalid"})

    if info["role"] == "signer":
        client = request.client
        host = client.host if client else "unknown"
        ipv4 = host if ":" not in host else None
        ipv6 = host if ":" in host else None
        ua = request.headers.get("user-agent", "")

        f = lock_state(_workdir)
        try:
            state = json.load(f)
            s = ensure_signer(state, info["id"])
            if ipv4:
                s["ip"] = ipv4
            if ipv6:
                s["ipv6"] = ipv6
            s["user_agent"] = ua
            f.seek(0)
            f.truncate()
            json.dump(state, f, indent=2)
        finally:
            unlock_state(f)

    return JSONResponse(info)


@app.get("/api/pages")
async def api_pages(request: Request):
    get_user(request)
    return JSONResponse({"pages": _pages, "total": len(_pages)})


@app.get("/api/status")
async def api_status(request: Request):
    get_user(request)
    state = read_state(_workdir)
    signers = {}
    for s in _config.signers:
        st = state.get("signers", {}).get(s.id, {})
        signers[s.id] = {
            "full_name": s.full_name,
            "nickname": s.nickname,
            "agreed_pages": st.get("agreed_pages", []),
            "rejected": st.get("rejected", False),
            "final_agreed": st.get("final_agreed", False),
            "geolocation": st.get("geolocation"),
        }
    return JSONResponse({
        "signers": signers,
        "proof_generated": state.get("proof_generated", False),
    })


@app.post("/api/me/state")
async def api_me_state(request: Request):
    user = get_user(request)
    if user["role"] != "signer":
        raise HTTPException(403, detail="Not a signer")
    state = read_state(_workdir)
    return JSONResponse(state.get("signers", {}).get(user["id"], {}))


@app.post("/api/page/{n}/agree")
async def api_page_agree(n: int, request: Request):
    user = get_user(request)
    if user["role"] != "signer":
        raise HTTPException(403, detail="Not a signer")
    body = await request.json()
    name = body.get("name", "")
    if name.strip().lower() != user["nickname"].lower():
        return JSONResponse({"ok": False, "error": "Nickname does not match"})

    f = lock_state(_workdir)
    try:
        state = json.load(f)
        s = ensure_signer(state, user["id"])
        if s.get("rejected"):
            return JSONResponse({"ok": False, "error": "Already rejected"})
        if s.get("final_agreed"):
            return JSONResponse({"ok": False, "error": "Already agreed finally"})
        if n in s.get("agreed_pages", []):
            return JSONResponse({"ok": False, "error": "Already agreed"})
        s.setdefault("agreed_pages", []).append(n)
        f.seek(0)
        f.truncate()
        json.dump(state, f, indent=2)
    finally:
        unlock_state(f)
    return JSONResponse({"ok": True})


@app.post("/api/final/reject")
async def api_reject(request: Request):
    user = get_user(request)
    if user["role"] != "signer":
        raise HTTPException(403, detail="Not a signer")
    body = await request.json()
    name = body.get("name", "")
    if name.strip() != user["full_name"]:
        return JSONResponse({"ok": False, "error": "Full name does not match"})

    f = lock_state(_workdir)
    try:
        state = json.load(f)
        s = ensure_signer(state, user["id"])
        if s.get("rejected"):
            return JSONResponse({"ok": False, "error": "Already rejected"})
        if s.get("final_agreed"):
            return JSONResponse({"ok": False, "error": "Already agreed finally"})
        s["rejected"] = True
        f.seek(0)
        f.truncate()
        json.dump(state, f, indent=2)
    finally:
        unlock_state(f)
    return JSONResponse({"ok": True})


@app.post("/api/final/agree")
async def api_final_agree(request: Request):
    user = get_user(request)
    if user["role"] != "signer":
        raise HTTPException(403, detail="Not a signer")
    body = await request.json()
    name = body.get("name", "")
    if name.strip() != user["full_name"]:
        return JSONResponse({"ok": False, "error": "Full name does not match"})

    lat = body.get("latitude")
    lng = body.get("longitude")

    proof_generated = False
    num_pages = len(_pages)

    f = lock_state(_workdir)
    try:
        state = json.load(f)
        s = ensure_signer(state, user["id"])
        if s.get("rejected"):
            return JSONResponse({"ok": False, "error": "Already rejected"})
        if s.get("final_agreed"):
            return JSONResponse({"ok": False, "error": "Already agreed finally"})
        if len(s.get("agreed_pages", [])) != num_pages:
            return JSONResponse({"ok": False, "error": "Not all pages agreed"})

        if lat is not None and lng is not None:
            s["geolocation"] = {"lat": lat, "lng": lng}

        s["final_agreed"] = True
        s["final_agreed_at"] = datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

        all_agreed = all(
            state.get("signers", {}).get(signer.id, {}).get("final_agreed")
            for signer in _config.signers
        )
        if all_agreed:
            state["proof_generated"] = True
            proof_generated = True

        f.seek(0)
        f.truncate()
        json.dump(state, f, indent=2)
    finally:
        unlock_state(f)

    if proof_generated:
        state_after = read_state(_workdir)
        generate_proof(state_after, _config, _pages, _workdir)

    result = {"ok": True}
    if proof_generated:
        result["proof_generated"] = True
    return JSONResponse(result)


@app.get("/api/proof/download")
async def api_proof_download(request: Request):
    get_user(request)
    state = read_state(_workdir)
    if not state.get("proof_generated"):
        raise HTTPException(404, detail="Proof not yet available")

    proof_files = sorted(_workdir.glob("proof_*.zip"))
    if not proof_files:
        raise HTTPException(404, detail="Proof file not found")

    return FileResponse(
        path=proof_files[-1],
        media_type="application/zip",
        filename="proof_of_agreement.zip",
    )


# ── Startup helper ───────────────────────────────────────────────────
def init_app(config_path: Path, workdir: Path) -> None:
    global _config, _pages, _token_map, _workdir, _spa_html

    _config = load_config(config_path)
    _workdir = workdir.resolve()
    _workdir.mkdir(parents=True, exist_ok=True)

    verify_cert_chain(_config.pki)
    init_state(_workdir)

    for p in _config.readme_pages:
        with open(p) as f:
            _pages.append(f.read())

    _token_map = build_token_map(_config)

    spa_path = Path(__file__).parent / "templates" / "index.html"
    with open(spa_path) as f:
        _spa_html = f.read()


# ── CLI ──────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="RRSign — Digital Agreement Signing")
    parser.add_argument("--config", type=Path, required=True, help="Path to config JSON")
    parser.add_argument("--workdir", type=Path, required=True, help="Working directory")
    parser.add_argument("--port", type=int, default=8000, help="HTTP port (default: 8000)")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    args = parser.parse_args()

    init_app(args.config, args.workdir)
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
