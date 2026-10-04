"""A11yForge production API.

Thin API layer over the verified scanning engine. The UI never contains scanning logic.
"""
import os
import re
from datetime import datetime, timezone
from uuid import uuid4
from urllib.parse import urlsplit

from fetch import Fetcher, is_public_url
from scan import analyze
from client_package import build_client_package
from repair import repair_html

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel, Field
except ImportError:
    FastAPI = None

if FastAPI:
    app = FastAPI(title="A11yForge API", version="1.4.0")
    allowed = [x.strip().rstrip("/") for x in os.getenv("A11YFORGE_CORS", "http://localhost:3000,http://127.0.0.1:3000").split(",") if x.strip()]
    app.add_middleware(CORSMiddleware, allow_origins=allowed, allow_credentials=False, allow_methods=["GET","POST","OPTIONS"], allow_headers=["Content-Type"])

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
            raise ValueError("Only HTTP(S) URLs are supported    @app.post("/api/scan")
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
                "repeat_load_status": "PENDING",
                "http_status": first["status"],
                "fetch_ms": round(first["elapsed"] * 1000),
            })

            second = fetcher.page(first["final"])
            if second["state"] == "OK":
                src2 = second["body"].decode(second.get("charset") or "utf-8", "replace")
                second_result = analyze(src2, second["final"], second["headers"])
                keys = {(f["signature"], f["occurrence"]) for f in second_result["findings"]}
                result["findings"] = [f for f in result["findings"] if (f["signature"], f["occurrence"]) in keys]
                result["verified_loads"] = 2
                result["repeat_load_status"] = "CONFIRMED"
            else:
                result["repeat_load_status"] = "FAILED"
                result["repeat_load_error"] = second.get("error") or second["state"]

            try:
                from rendered_playwright import PlaywrightVerifier, CONFIRMED, ERROR
                verifier = PlaywrightVerifier(timeout_ms=20000, settle_ms=900)
                statuses = verifier.verify(first["final"], result["findings"])
                kept = []
                browser_errors = []
                for f in result["findings"]:
                    status = statuses.get((f["signature"], f["occurrence"]), ERROR)
                    item = {**f, "rendered_verification": status}
                    if status == CONFIRMED:
                        kept.append(item)
                    elif status == ERROR:
                        browser_errors.append(item)
                result["candidate_findings"] = browser_errors
                result["findings"] = kept
                result["rendered_status"] = verifier.last_evidence.get("status", "UNKNOWN")
                result["rendered_evidence"] = verifier.last_evidence
            except Exception as exc:
                result["candidate_findings"] = result["findings"]
                result["findings"] = []
                result["rendered_status"] = "ERROR"
                result["rendered_evidence"] = {"status": "ERROR", "error": type(exc).__name__ + ": " + str(exc)[:300]}

            result["finding_count"] = len(result["findings"])
            result["candidate_count"] = len(result.get("candidate_findings", []))
            repair_result = repair_html(src, result["findings"])
            package = build_client_package(result, repair_result)
            return {
                "scan_id": datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-") + uuid4().hex[:8],
                "product": "A11yForge",
                "result": result,
                "repair": repair_result,
                "package": package,
            }
        except HTTPException:
            raise
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except Exception:
            raise HTTPException(status_code=500, detail="Scanner failed safely. Check server logs for the diagnostic.")

n:
            raise
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except Exception as exc:
            raise HTTPException(status_code=500, detail="Scanner failed safely. Check server logs for the diagnostic.")
else:
    app = None
