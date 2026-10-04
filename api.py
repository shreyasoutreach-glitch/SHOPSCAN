"""A11yForge production API.

Thin API layer over the verified scanning engine. The UI never contains scanning logic.
"""
import os
import re
import threading
import time
from datetime import datetime, timezone
from uuid import uuid4
from urllib.parse import urlsplit

from fetch import Fetcher, is_public_url
from scan import analyze
from client_package import build_client_package
from repair import repair_html
from persistence import save_scan, configured, init_schema
from crawl import discover
from overlay_signatures import detect_source_overlays
from evidence_ledger import assessment_ledger

try:
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel, Field
except ImportError:
    FastAPI = None

if FastAPI:
    app = FastAPI(title="A11yForge API", version="1.6.0")
    allowed = [x.strip().rstrip("/") for x in os.getenv(
        "A11YFORGE_CORS",
        "http://localhost:3000,http://127.0.0.1:3000"
    ).split(",") if x.strip()]
    if configured():
        try:
            init_schema()
        except Exception:
            pass
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed,
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type"],
    )

    class ScanRequest(BaseModel):
        url: str = Field(min_length=4, max_length=2048)

    _scan_slots = threading.BoundedSemaphore(2)
    _rate_lock = threading.Lock()
    _rate_window = {}

    def _allow_request(client_key):
        now = time.time()
        limit = max(1, int(os.getenv("A11YFORGE_RATE_LIMIT", "12")))
        with _rate_lock:
            bucket = [t for t in _rate_window.get(client_key, []) if now - t < 60]
            if len(bucket) >= limit:
                _rate_window[client_key] = bucket
                return False
            bucket.append(now)
            _rate_window[client_key] = bucket
            if len(_rate_window) > 2000:
                stale = [k for k, values in _rate_window.items() if not values or now - values[-1] >= 60]
                for key in stale[:1000]:
                    _rate_window.pop(key, None)
            return True


    def normalize_url(value: str) -> str:
        value = value.strip()
        if not re.match(r"^https?://", value, re.I):
            value = "https://" + value
        p = urlsplit(value)
        if not p.hostname or p.username or p.password:
            raise ValueError("Enter a valid public website URL.")
        if p.scheme.lower() not in ("http", "https"):
            raise ValueError("Only HTTP(S) URLs are supported.")
        if not is_public_url(value):
            raise ValueError("The destination must resolve only to a public internet address.")
        return value

    @app.get("/health")
    def health():
        return {"ok": True, "product": "A11yForge", "version": "1.6.0"}

    @app.post("/api/scan")
    def scan(req: ScanRequest, request: Request):
        client_key = request.client.host if request.client else "unknown"
        if not _allow_request(client_key):
            raise HTTPException(status_code=429, detail="Scan rate limit reached. Try again in a minute.")
        if not _scan_slots.acquire(blocking=False):
            raise HTTPException(status_code=429, detail="Scanner is at capacity. Try again shortly.")
        try:
            url = normalize_url(req.url)
            fetcher = Fetcher(delay=0.4, timeout=20, max_bytes=3_000_000)
            first = fetcher.page(url)
            if first["state"] != "OK":
                raise HTTPException(
                    status_code=422,
                    detail=f"Could not fetch site: {first['state']} ({first['status']}).",
                )

            src = first["body"].decode(first.get("charset") or "utf-8", "replace")
            result = analyze(src, first["final"], first["headers"])
            result["scanner_version"] = "1.6.0"
            result["overlay_evidence"] = {"source": [{"vendor":v,"confidence":"MEDIUM","signals":["static-signature"],"source_observed":True,"runtime_observed":False} for v in result.get("context",{}).get("overlays",[])]}
            result.update({
                "url": first["final"],
                "domain": urlsplit(first["final"]).hostname,
                "verified_loads": 1,
                "repeat_load_status": "PENDING",
                "http_status": first["status"],
                "fetch_ms": round(first["elapsed"] * 1000),
                "discovered_pages": discover(first["final"], src, max_pages=max(1, min(4, int(os.getenv("A11YFORGE_CRAWL_PAGES", "4"))))),
            })

            second = fetcher.page(first["final"])
            if second["state"] == "OK":
                src2 = second["body"].decode(second.get("charset") or "utf-8", "replace")
                second_result = analyze(src2, second["final"], second["headers"])
                keys = {
                    (f["signature"], f["occurrence"])
                    for f in second_result["findings"]
                }
                result["findings"] = [
                    f for f in result["findings"]
                    if (f["signature"], f["occurrence"]) in keys
                ]
                result["verified_loads"] = 2
                result["repeat_load_status"] = "CONFIRMED"
            else:
                result["repeat_load_status"] = "FAILED"
                result["repeat_load_error"] = second.get("error") or second["state"]

            verifier = None
            try:
                from rendered_playwright import PlaywrightVerifier, CONFIRMED, ERROR

                verifier = PlaywrightVerifier(timeout_ms=20000, settle_ms=900)
                static_candidates = list(result["findings"])
                statuses = verifier.verify(first["final"], static_candidates)
                kept = []
                candidate_findings = []

                for finding in static_candidates:
                    status = statuses.get(
                        (finding["signature"], finding["occurrence"]),
                        ERROR,
                    )
                    item = {**finding, "rendered_verification": status}
                    if status == CONFIRMED:
                        kept.append(item)
                    else:
                        candidate_findings.append(item)

                result["candidate_findings"] = candidate_findings
                result["findings"] = kept
                result["verified_finding_count"] = len(kept)
                result["candidate_finding_count"] = len(candidate_findings)
                result["rendered_status"] = verifier.last_evidence.get(
                    "status", "UNKNOWN"
                )
                result["rendered_evidence"] = verifier.last_evidence
                runtime_overlays=[]
                for vp in verifier.last_evidence.get("viewports",[]):
                    runtime_overlays.extend(detect_source_overlays(
                        script_urls=vp.get("script_urls",[]),
                        iframe_urls=vp.get("iframe_urls",[]),
                        markers=vp.get("marker_hints",[]),
                        globals=vp.get("global_hints",[])
                    ))
                by_vendor={}
                for item in runtime_overlays:
                    by_vendor.setdefault(item["vendor"],[]).extend(item.get("signals",[]))
                result["overlay_evidence"]["runtime"]=[{"vendor":v,"confidence":"HIGH" if len(set(s))>=2 else "MEDIUM","signals":sorted(set(s))[:12],"source_observed":bool(result["overlay_evidence"].get("source")),"runtime_observed":True} for v,s in by_vendor.items()]
            except Exception as exc:
                result["candidate_findings"] = [{**f, "rendered_verification": ERROR} for f in result.get("findings", [])]
                result["findings"] = []
                result["rendered_status"] = "ERROR"
                result["overlay_evidence"] = result.get("overlay_evidence",{"source":[],"runtime":[]})
                result["rendered_evidence"] = {
                    "status": "ERROR",
                    "error": type(exc).__name__ + ": " + str(exc)[:300],
                }

            # Interaction audit is independent of static candidates. A page can have
            # serious keyboard/focus defects even when source-level rules find nothing.
            try:
                from interaction import audit as interaction_audit
                interaction_findings, interaction_evidence = interaction_audit(
                    first["final"], timeout_ms=15000, settle_ms=700
                )
                for item in interaction_findings:
                    item["url"] = first["final"]
                    item["source_repairable"] = False
                result["interaction_findings"] = interaction_findings
                result["interaction_evidence"]["accessibility_tree"] = interaction_evidence.get("accessibility_tree",{})
                result["interaction_evidence"] = interaction_evidence
                result["interaction_status"] = interaction_evidence.get("status", "UNKNOWN")
                result["findings"].extend(interaction_findings)
            except Exception as exc:
                result["interaction_findings"] = []
                result["interaction_status"] = "ERROR"
                result["interaction_evidence"] = {
                    "status": "ERROR",
                    "error": type(exc).__name__ + ": " + str(exc)[:300],
                }

            # Scan the bounded same-origin page set discovered from the storefront homepage.
            # The homepage is already represented above, so only additional pages are merged.
            try:
                from multipage import assess_pages
                page_reports = assess_pages(
                    first["final"],
                    result.get("discovered_pages", []),
                    fetcher=fetcher,
                    max_pages=max(1, min(4, int(os.getenv("A11YFORGE_CRAWL_PAGES", "4")))),
                )
                result["page_reports"] = page_reports
                result["scanned_pages"] = len(page_reports)
                for page_report in page_reports:
                    final_url = page_report.get("final_url") or page_report.get("url")
                    if final_url == first["final"]:
                        continue
                    for finding in page_report.get("verified_findings", []):
                        finding["source_page"] = final_url
                        finding["source_repairable"] = False
                        result["findings"].append(finding)
                    for finding in page_report.get("candidate_findings", []):
                        finding["source_page"] = final_url
                        finding["source_repairable"] = False
                        result.setdefault("candidate_findings", []).append(finding)
                result["multipage_status"] = "OK"
            except Exception as exc:
                result["page_reports"] = []
                result["scanned_pages"] = 1
                result["multipage_status"] = "ERROR"
                result["multipage_error"] = type(exc).__name__ + ": " + str(exc)[:300]

            # Browser-discovered findings are independent of static candidates.
            # Add only genuinely new hydrated-DOM defects to the verified queue.
            try:
                dynamic = getattr(verifier, "last_dynamic_findings", [])
            except Exception:
                dynamic = []
            existing={(f.get("base_rule") or f.get("rule"), f.get("signature"), f.get("occurrence")) for f in result.get("findings",[])}
            for f in dynamic:
                key=(f.get("base_rule") or f.get("rule"),f.get("signature"),f.get("occurrence"))
                if key in existing: continue
                f["source_repairable"]=False
                f["rendered_verification"]="CONFIRMED"
                result["findings"].append(f)
                existing.add(key)
            result["finding_count"] = len(result["findings"])
            result["candidate_count"] = len(result.get("candidate_findings", []))
            result["assessment_status"] = "VERIFIED" if result.get("rendered_status") == "OK" else "VERIFICATION_LIMIT"

            # Only source-backed findings can produce source patches. Interaction
            # findings remain evidence/review items and never get fake source offsets.
            repair_input = [f for f in result["findings"] if f.get("source_repairable", True)]
            if not repair_input and result.get("rendered_status") in {"ERROR", "PARTIAL"}:
                repair_input = [
                    f for f in result.get("candidate_findings", [])
                    if f.get("rendered_verification") == ERROR and f.get("source_repairable", True)
                ]
            repair_result = repair_html(src, repair_input)
            if repair_input is not result["findings"]:
                for item in repair_result.get("repairs", []):
                    item["verification_scope"] = "static_candidate_unverified"

            if repair_result.get("changed"):
                try:
                    from regression import verify_patch
                    repair_result["regression"] = verify_patch(
                        src,
                        repair_result.get("html", src),
                        repair_result.get("repairs", []),
                    )
                except Exception as exc:
                    repair_result["regression"] = {
                        "status": "ERROR",
                        "error": type(exc).__name__ + ": " + str(exc)[:300],
                    }
            else:
                repair_result["regression"] = {"status": "NOT_RUN", "checks": []}

            package = build_client_package(result, repair_result)
            scan_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-") + uuid4().hex[:8]
            persistence_status = "PERSISTED" if save_scan(scan_id, result) else "STATELESS"
            result["persistence_status"] = persistence_status
            result["evidence_ledger"] = assessment_ledger(result)
            result["evidence_head_hash"] = result["evidence_ledger"].get("head_hash")
            package = build_client_package(result, repair_result)

            return {
                "scan_id": scan_id,
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
            raise HTTPException(
                status_code=500,
                detail="Scanner failed safely. Check server logs for the diagnostic.",
            )
        finally:
            _scan_slots.release()
else:
    app = None
