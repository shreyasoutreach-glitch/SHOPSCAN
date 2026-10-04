"""Bounded multi-page assessment for public storefronts.

The crawler is intentionally small and deterministic. It scans a prioritized set of same-origin
pages, repeats source analysis, and verifies surviving candidates in Chromium. It never submits
forms or performs transactional actions.
"""
from urllib.parse import urlsplit
from fetch import Fetcher
from scan import analyze
from rendered_playwright import PlaywrightVerifier, CONFIRMED, ERROR

def assess_pages(start_url, discovered_pages, fetcher=None, max_pages=4):
    pages=[]
    urls=[]
    seen=set()
    for u in [start_url]+list(discovered_pages or []):
        host=(urlsplit(u).hostname or "").lower()
        if not host or host != (urlsplit(start_url).hostname or "").lower():
            continue
        if u in seen: continue
        seen.add(u); urls.append(u)
        if len(urls)>=max_pages: break

    fetcher=fetcher or Fetcher(delay=0.35, timeout=20, max_bytes=3_000_000)
    for url in urls:
        row={"url":url,"status":"ERROR","findings":[],"advisories":[],"rendered_status":"ERROR"}
        try:
            first=fetcher.page(url)
            if first["state"]!="OK":
                row["error"]=first.get("error") or first["state"]
                pages.append(row); continue
            src=first["body"].decode(first.get("charset") or "utf-8","replace")
            a=analyze(src,first["final"],first.get("headers"))
            second=fetcher.page(first["final"])
            if second["state"]=="OK":
                src2=second["body"].decode(second.get("charset") or "utf-8","replace")
                b=analyze(src2,second["final"],second.get("headers"))
                keys={(x["signature"],x["occurrence"]) for x in b["findings"]}
                findings=[x for x in a["findings"] if (x["signature"],x["occurrence"]) in keys]
                advkeys={(x["signature"],x["occurrence"]) for x in b["advisories"]}
                advisories=[x for x in a["advisories"] if (x["signature"],x["occurrence"]) in advkeys]
                row["repeat_load_status"]="CONFIRMED"
            else:
                findings=[]; advisories=[]; row["repeat_load_status"]="FAILED"
            verifier=PlaywrightVerifier(timeout_ms=18000,settle_ms=700,viewports=((1440,1000),(390,844)))
            verdicts=verifier.verify(first["final"],findings)
            confirmed=[]
            candidates=[]
            for f in findings:
                status=verdicts.get((f["signature"],f["occurrence"]),ERROR)
                item={**f,"url":first["final"],"rendered_verification":status}
                if status==CONFIRMED: confirmed.append(item)
                else: candidates.append(item)
            row.update({
                "status":"OK",
                "final_url":first["final"],
                "http_status":first["status"],
                "verified_findings":confirmed,
                "candidate_findings":candidates,
                "advisories":advisories,
                "finding_count":len(confirmed),
                "candidate_count":len(candidates),
                "rendered_status":verifier.last_evidence.get("status","UNKNOWN"),
                "rendered_evidence":verifier.last_evidence,
                "limitations":a.get("limitations",[]),
            })
        except Exception as exc:
            row["error"]=type(exc).__name__+": "+str(exc)[:300]
        pages.append(row)
    return pages
