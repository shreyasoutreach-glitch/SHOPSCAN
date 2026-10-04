"""A11yForge production API.

Thin API layer over the verified scanning engine. The UI never contains scanning logic.
"""
import os
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

from fetch import Fetcher
from scan import analyze
from client_package import build_client_package

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel, Field
except ImportError:
    FastAPI = None

if FastAPI:
    app = FastAPI(title="A11yForge API", version="1.4.0")
    allowed = [x.strip().rstrip("/") for x in os.getenv("A11YFORGE_CORS", "*").split(",") if x.strip()]
    app.add_middleware(CORSMiddleware, allow_origins=allowed, allow_credentials=False, allow_methods=["*"], allow_headers=["*"])

    class ScanRequest(BaseModel):
        url: str = Field(min_length=4, max_length=2048)

    def normalize_url(value: str) -> str:
        value = value.strip()
        if not re.match(r"^https?://", value, re.I):
            value = "https://" + value
        p = urlsplit(value)
        if not p.hostname or p.username or p.password:
            raise ValueError("Enter a valid public website URL.")
        if p.scheme.lower() not in ("http", "https"):
            raise ValueError("Only HTTP(S) URLs are supported.")
        return value

    @app.get("/health")
    def health():
        return {"ok": True, "product": "A11yForge", "version": "1.4.0"}

    @app.post("/api/scan")
    def scan(req: ScanRequest):
        try:
            url = normalize_url(req.url)
            fetcher = Fetcher(delay=0.4, timeout=20, max_bytes=3_000_000)
            first = fetcher.page(url)
            if first["state"] != "OK":
                raise HTTPException(status_code=422, detail=f"Could not fetch site: {first['state']} ({first['status']}).")
            src = first["body"].decode(first.get("charset") or "utf-8", "replace")
            result = analyze(src, first["final"], first["headers"])
            result.update({
                "url": first["final"],
                "domain": urlsplit(first["final"]).hostname,
                "verified_loads": 1,
                "http_status": first["status"],
                "fetch_ms": round(first["elapsed"] * 1000),
            })

            # Browser verification is deliberately isolated. A browser failure becomes evidence,
            # never a fabricated positive result.
            try:
                from rendered_playwright import PlaywrightVerifier, CONFIRMED, NOT_REPRODUCED
                verifier = PlaywrightVerifier(timeout_ms=20000, settle_ms=900)
                statuses = verifier.verify(first["final"], result["findings"])
                kept = []
                for f in result["findings"]:
                    status = statuses.get((f["signature"], f["occurrence"]))
                    f = {**f, "rendered_verification": "CONFIRMED" if status == CONFIRMED else "NOT_REPRODUCED"}
                    if status == CONFIRMED:
                        kept.append(f)
                result["findings"] = kept
                result["rendered_status"] = verifier.last_evidence.get("status", "UNKNOWN")
                result["rendered_evidence"] = verifier.last_evidence
            except Exception as exc:
                result["rendered_status"] = "ERROR"
                result["rendered_evidence"] = {"status": "ERROR", "error": type(exc).__name__ + ": " + str(exc)[:300]}

            package = build_client_package(result)
            return {
                "scan_id": datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"),
                "product": "A11yForge",
                "result": result,
                "package": package,
            }
        except HTTPException:
            raise
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except Exception as exc:
            raise HTTPException(status_code=500, detail="Scanner failed safely. Check server logs for the diagnostic.")
else:
    app = None
