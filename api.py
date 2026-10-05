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
from persistence import save_scan, configured, init_schema, save_authorization, get_authorization, log_scan_request
from crawl import discover
from overlay_signatures import detect_source_overlays
from evidence_ledger import assessment_ledger
from overlay_truth import run_overlay_truth_test
from authorization import NOT_REQUESTED, REQUESTED, GRANTED, DECLINED, normalize_domain, issue_token, token_digest, instructions, verify as verify_domain
from scan_policy import PUBLIC_PREVIEW, blocked_domain, apply_suppressions, scan_scope\nfrom agency import normalize_name, share_token, share_digest, expiry_iso\nfrom monitoring import snapshot as monitoring_snapshot, diff as monitoring_diff\nfrom persistence import (create_workspace, list_workspaces, create_client, list_clients, create_share_link, get_share_link, count_workspace_clients,\n                          add_monitor_target, due_monitor_targets, record_monitor_run, latest_monitor_snapshot, list_monitor_events, latest_scan_for_client, list_monitor_targets_for_client)

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

    class DomainRequest(BaseModel):
        domain: str = Field(min_length=3, max_length=253)

    @app.post("/api/authorization/request")
    def authorization_request(req: DomainRequest):
        try:
            domain=normalize_domain(req.domain)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        if blocked_domain(domain):
            return {"domain":domain,"state":DECLINED,"reason":"Domain is present on an opt-out or do-not-scan list."}
        token=issue_token()
        save_authorization(domain,REQUESTED,token_digest(token))
        return {"domain":domain,"state":REQUESTED,"verification":instructions(domain,token)}

    @app.post("/api/authorization/verify-token")
    def authorization_verify_token(req: DomainRequest, request: Request):
        try:
            domain=normalize_domain(req.domain)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        row=get_authorization(domain)
        token=request.headers.get("X-A11yForge-Verification","").strip()
        if not row or row.get("state")!=REQUESTED or not token or token_digest(token)!=row.get("token_digest"):
            raise HTTPException(status_code=409, detail="No matching pending authorization token.")
        fetcher=Fetcher(delay=2.0,timeout=15,max_bytes=3_000_000)
        result=verify_domain(domain,token,fetcher)
        if not result["granted"]:
            raise HTTPException(status_code=422, detail="Verification token was not found in the domain DNS TXT record or homepage meta tag.")
        save_authorization(domain,GRANTED,token_digest(token),result["method"])
        return {"domain":domain,"state":GRANTED,"verification_method":result["method"]}

    @app.post("/api/authorization/decline")
    def authorization_decline(req: DomainRequest):
        try:
            domain=normalize_domain(req.domain)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        save_authorization(domain,DECLINED,token_digest(issue_token()))
        return {"domain":domain,"state":DECLINED}

    def _agency_key(request):
        expected=os.getenv("A11YFORGE_AGENCY_KEY","").strip()
        supplied=request.headers.get("X-A11yForge-Agency-Key","").strip()
        if not expected or not supplied or supplied!=expected:
            raise HTTPException(status_code=403, detail="Agency workspace authorization is not configured or the supplied key is invalid.")
        return supplied

    class WorkspaceRequest(BaseModel):
        name: str = Field(min_length=1,max_length=160)

    class ClientRequest(BaseModel):
        workspace_id: int
        name: str = Field(min_length=1,max_length=160)
        domain: str = Field(min_length=3,max_length=253)

    class MonitorRequest(BaseModel):
        client_id: int
        url: str = Field(min_length=4,max_length=2048)
        cadence_minutes: int = Field(default=1440,ge=60,le=10080)

    @app.post("/api/agency/workspaces")
    def agency_workspace_create(req: WorkspaceRequest, request: Request):
        key=_agency_key(request)
        if not configured():
            raise HTTPException(status_code=503,detail="Agency persistence requires DATABASE_URL.")
        return {"id":create_workspace(normalize_name(req.name),key,normalize_name(req.brand_name) if req.brand_name else None),"name":req.name.strip()}

    @app.get("/api/agency/workspaces")
    def agency_workspace_list(request: Request):
        key=_agency_key(request)
        if not configured():
            raise HTTPException(status_code=503,detail="Agency persistence requires DATABASE_URL.")
        return {"workspaces":list_workspaces(key)}

    @app.post("/api/agency/clients")
    def agency_client_create(req: ClientRequest, request: Request):
        key=_agency_key(request)
        if not configured():
            raise HTTPException(status_code=503,detail="Agency persistence requires DATABASE_URL.")
        workspaces=list_workspaces(key)
        if not any(int(w["id"])==req.workspace_id for w in workspaces):
            raise HTTPException(status_code=404,detail="Workspace not found.")
        domain=normalize_domain(req.domain)
        return {"id":create_client(req.workspace_id,normalize_name(req.name),domain),"domain":domain}

    class BulkClientRequest(BaseModel):
        workspace_id: int
        csv_text: str = Field(min_length=1,max_length=2_000_000)

    @app.post("/api/agency/clients/bulk")
    def agency_client_bulk(req: BulkClientRequest, request: Request):
        key=_agency_key(request)
        if not configured():
            raise HTTPException(status_code=503,detail="Agency persistence requires DATABASE_URL.")
        if not any(int(w["id"])==req.workspace_id for w in list_workspaces(key)):
            raise HTTPException(status_code=404,detail="Workspace not found.")
        import csv, io
        rows=list(csv.DictReader(io.StringIO(req.csv_text)))
        if not rows or "name" not in rows[0] or "domain" not in rows[0]:
            raise HTTPException(status_code=400,detail="CSV must contain name and domain columns.")
        max_clients=int(os.getenv("A11YFORGE_MAX_CLIENTS","100"))
        if count_workspace_clients(req.workspace_id)+len(rows)>max_clients:
            raise HTTPException(status_code=409,detail="Workspace client limit reached.")
        created=[]
        for row in rows:
            try:
                name=normalize_name(row.get("name",""))
                domain=normalize_domain(row.get("domain",""))
                created.append({"id":create_client(req.workspace_id,name,domain),"name":name,"domain":domain})
            except ValueError as exc:
                raise HTTPException(status_code=400,detail=str(exc))
        return {"created":created,"count":len(created)}

    @app.get("/api/agency/clients/{client_id}/dashboard")
    def agency_client_dashboard(client_id:int,request:Request):
        key=_agency_key(request)
        if not configured(): raise HTTPException(status_code=503,detail="Agency persistence requires DATABASE_URL.")
        clients=[]
        for w in list_workspaces(key): clients.extend(list_clients(int(w["id"])))
        if not any(int(x["id"])==client_id for x in clients): raise HTTPException(status_code=404,detail="Client not found.")
        # Dashboard data is evidence state only. It does not infer compliance.
        events=[]
        targets=list_monitor_targets_for_client(client_id)
        for target in targets: events.extend(list_monitor_events(target["id"],limit=5))
        return {"client_id":client_id,"monitor_events":events[:20],"status":"EVIDENCE_HISTORY"}
    @app.get("/api/agency/workspaces/{workspace_id}/clients")
    def agency_client_list(workspace_id: int, request: Request):
        key=_agency_key(request)
        if not configured():
            raise HTTPException(status_code=503,detail="Agency persistence requires DATABASE_URL.")
        if not any(int(w["id"])==workspace_id for w in list_workspaces(key)):
            raise HTTPException(status_code=404,detail="Workspace not found.")
        return {"clients":list_clients(workspace_id)}

    @app.post("/api/agency/monitor-targets")
    def agency_monitor_create(req: MonitorRequest, request: Request):
        key=_agency_key(request)
        if not configured():
            raise HTTPException(status_code=503,detail="Monitoring persistence requires DATABASE_URL.")
        all_clients=[]
        for w in list_workspaces(key):
            all_clients.extend(list_clients(int(w["id"])))
        client=next((x for x in all_clients if int(x["id"])==req.client_id),None)
        if not client:
            raise HTTPException(status_code=404,detail="Client not found.")
        url=normalize_url(req.url)
        domain=urlsplit(url).hostname
        auth=get_authorization(domain) or {}
        if auth.get("state")!=GRANTED:
            raise HTTPException(status_code=403,detail="Monitoring requires GRANTED domain authorization.")
        tid=add_monitor_target(url,req.cadence_minutes,client=client["id"])
        return {"id":tid,"url":url,"cadence_minutes":req.cadence_minutes,"authorization_state":GRANTED}

    @app.get("/api/agency/monitor-targets/{target_id}/events")
    def agency_monitor_events(target_id: int, request: Request):
        _agency_key(request)
        if not configured():
            raise HTTPException(status_code=503,detail="Monitoring persistence requires DATABASE_URL.")
        return {"events":list_monitor_events(target_id)}

    @app.post("/api/monitor/run-due")
    def monitor_run_due(request: Request):
        secret=os.getenv("A11YFORGE_MONITOR_SECRET","").strip()
        supplied=request.headers.get("X-A11yForge-Monitor-Secret","").strip()
        if not secret or supplied!=secret:
            raise HTTPException(status_code=403,detail="Invalid monitor secret.")
        if not configured():
            raise HTTPException(status_code=503,detail="Monitoring persistence requires DATABASE_URL.")
        import urllib.request
        base=os.getenv("A11YFORGE_INTERNAL_URL","").strip().rstrip("/")
        if not base:
            raise HTTPException(status_code=503,detail="A11YFORGE_INTERNAL_URL is not configured.")
        outcomes=[]
        for target in due_monitor_targets(limit=10):
            try:
                body=json.dumps({"url":target["url"]}).encode()
                req=urllib.request.Request(base+"/api/scan",data=body,headers={"Content-Type":"application/json","User-Agent":"A11yForge-Monitor/1.0"},method="POST")
                with urllib.request.urlopen(req,timeout=120) as resp:
                    payload=json.loads(resp.read().decode())
                current=monitoring_snapshot(payload["result"])
                previous=latest_monitor_snapshot(target["id"])
                changes=monitoring_diff(previous,current)
                record_monitor_run(target["id"],payload["scan_id"],changes["status"],previous,current,changes)
                outcomes.append({"target_id":target["id"],"scan_id":payload["scan_id"],"status":changes["status"],"new":changes["new_count"],"fixed":changes["fixed_count"]})
            except Exception as exc:
                outcomes.append({"target_id":target["id"],"status":"ERROR","error":type(exc).__name__+":"+str(exc)[:240]})
        return {"processed":len(outcomes),"outcomes":outcomes}

    @app.post("/api/agency/clients/{client_id}/share")
    def agency_share_create(client_id: int, request: Request):
        key=_agency_key(request)
        if not configured():
            raise HTTPException(status_code=503,detail="Agency persistence requires DATABASE_URL.")
        clients=[]
        for w in list_workspaces(key):
            clients.extend(list_clients(int(w["id"])))
        if not any(int(c["id"])==client_id for c in clients):
            raise HTTPException(status_code=404,detail="Client not found.")
        token=share_token()
        expiry=expiry_iso(7)
        sid=create_share_link(client_id,share_digest(token),expiry)
        return {"id":sid,"token":token,"expires_at":expiry,"human_review_required":True}

    @app.get("/api/share/{token}")
    def agency_share_view(token: str):
        if not configured():
            raise HTTPException(status_code=503,detail="Shared evidence requires DATABASE_URL.")
        link=get_share_link(share_digest(token))
        if not link:
            raise HTTPException(status_code=404,detail="Share link is invalid or expired.")
        result=latest_scan_for_client(link["client_id"])
        if not result:
            raise HTTPException(status_code=404,detail="No retained scan evidence is available for this client.")
        return {"client_id":link["client_id"],"result":result,"report_disclaimer":"Evidence report, not legal advice or certification."}
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
            domain=urlsplit(url).hostname
            auth_row=get_authorization(domain) or {}
            auth_state=auth_row.get("state",NOT_REQUESTED)
            request_id=uuid4().hex
            preview=PUBLIC_PREVIEW and auth_state!=GRANTED
            if blocked_domain(domain):
                log_scan_request(request_id,domain,url,auth_state,"BLOCKED_BY_POLICY",client_key,preview)
                raise HTTPException(status_code=403, detail="This domain is on an A11yForge do-not-scan or opt-out list.")
            if auth_state!=GRANTED and not preview:
                log_scan_request(request_id,domain,url,auth_state,"NOT_AUTHORIZED",client_key,False)
                raise HTTPException(status_code=403, detail="Domain authorization is required before scanning. Request ownership verification first.")
            scope=scan_scope(auth_state==GRANTED)
            log_scan_request(request_id,domain,url,auth_state,"ACCEPTED",client_key,preview)
            fetcher = Fetcher(delay=2.0, timeout=20, max_bytes=3_000_000)
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
                "authorization_state": auth_state,
                "scan_scope": scope,
                "verified_loads": 1,
                "repeat_load_status": "PENDING",
                "http_status": first["status"],
                "fetch_ms": round(first["elapsed"] * 1000),
                "discovered_pages": discover(first["final"], src, max_pages=scope["max_pages"]),
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
                source_overlays=result["overlay_evidence"].get("source",[])
                if source_overlays:
                    truth=run_overlay_truth_test(
                        first["final"],static_candidates,source_overlays,
                        lambda blocked: PlaywrightVerifier(timeout_ms=20000,settle_ms=900,blocked_vendors=blocked),
                        shipped=statuses,shipped_evidence=verifier.last_evidence
                    )
                    result["overlay_evidence"]["truth_test"]=truth
                    truth_by_key={(x["signature"],x["occurrence"]):x for x in truth.get("findings",[])}
                    for finding in result.get("findings",[]):
                        row=truth_by_key.get((finding.get("signature"),finding.get("occurrence",0)))
                        if row: finding["evidence_hash"]=row["evidence_hash"]
                else:
                    result["overlay_evidence"]["truth_test"]={"status":"NOT_APPLICABLE","vendors":[],"findings":[],"deterministic":True}
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
                    max_pages=scope["max_pages"],
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
            result["findings"]=apply_suppressions(domain,result["findings"])
            result["candidate_findings"]=apply_suppressions(domain,result.get("candidate_findings",[]))
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

            package = build_client_package(result, repair_result, source_html=src)
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
