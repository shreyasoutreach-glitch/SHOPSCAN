"""Network execution wrapper for ShopScan 1.1 with browser-backed verification."""
import csv,json,os,time
from concurrent.futures import ThreadPoolExecutor,as_completed
from fetch import Fetcher,canonical_url,decode_body
from scan import analyze,SCANNER_VERSION
from rendered import NOT_REPRODUCED, ERROR as RENDER_ERROR

DOMAINS_FILE=os.getenv("SHOPSCAN_DOMAINS","network_domains.txt")
OUT=os.getenv("SHOPSCAN_OUT","out")
WORKERS=max(1,min(int(os.getenv("SHOPSCAN_WORKERS","4")),8))
DELAY=float(os.getenv("SHOPSCAN_DELAY","2"))
MAX_BYTES=int(os.getenv("SHOPSCAN_MAX_BYTES","3000000"))
RENDERED=os.getenv("SHOPSCAN_RENDERED","playwright").strip().lower()

def make_verifier():
    if RENDERED in ("","none","off","not_run"):
        from rendered import NotRun
        return NotRun()
    if RENDERED in ("playwright","browser"):
        from rendered_playwright import PlaywrightVerifier
        return PlaywrightVerifier(
            timeout_ms=int(os.getenv("SHOPSCAN_RENDER_TIMEOUT_MS","20000")),
            settle_ms=int(os.getenv("SHOPSCAN_RENDER_SETTLE_MS","1200")))
    raise ValueError(f"unknown SHOPSCAN_RENDERED={RENDERED!r}")

def domains():
    with open(DOMAINS_FILE) as f:
        return list(dict.fromkeys(
            x.strip().lower().replace("https://","").replace("http://","").strip("/")
            for x in f if x.strip() and not x.lstrip().startswith("#")))

def scan_one(domain):
    f=Fetcher(delay=DELAY,max_bytes=MAX_BYTES)
    verifier=make_verifier()
    home=canonical_url("https://"+domain+"/")
    first=f.page(home)
    result={"domain":domain,"scanner_version":SCANNER_VERSION,
            "scanned_at":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
            "url":home,"status":first["state"],"http_status":first["status"],
            "error":first.get("error"),"shopify":None,"market":None,
            "findings":[],"advisories":[],"verified_loads":0,
            "rendered_verifier":verifier.name}
    if first["state"]!="OK": return result
    text,enc,method,repl=decode_body(first["body"],first.get("charset"))
    a=analyze(text,first["final"],first.get("headers"))
    result["encoding"]={"name":enc,"method":method,"replacement_chars":repl}
    result["shopify"]=a["context"]["platform"]
    result["market"]=a["context"]["market_label"]
    if a["context"]["platform"]["platform"]!="shopify":
        result["status"]="SKIPPED" if a["context"]["platform"]["platform"]=="not_detected" else "UNKNOWN"
        result["reason"]="no Shopify evidence" if result["status"]=="SKIPPED" else "possible Shopify only"
        return result
    second=f.page(home)
    if second["state"]!="OK":
        result["status"]="UNVERIFIED_SECOND_LOAD"
        result["error"]=second.get("error")
        return result
    text2,_,_,_=decode_body(second["body"],second.get("charset"))
    b=analyze(text2,second["final"],second.get("headers"))
    result["verified_loads"]=2
    keys={(x["signature"],x["occurrence"]) for x in b["findings"]}
    findings=[x for x in a["findings"] if (x["signature"],x["occurrence"]) in keys]
    advkeys={(x["signature"],x["occurrence"]) for x in b["advisories"]}
    advisories=[x for x in a["advisories"] if (x["signature"],x["occurrence"]) in advkeys]

    verdicts=verifier.verify(home,findings)
    rendered_counts={"CONFIRMED":0,"NOT_REPRODUCED":0,"ERROR":0,"NOT_RUN":0}
    kept=[]
    for x in findings:
        v=verdicts.get((x["signature"],x["occurrence"]),RENDER_ERROR)
        x["rendered_verification"]={"status":v,"verifier":verifier.name}
        rendered_counts[v]=rendered_counts.get(v,0)+1
        if v!=NOT_REPRODUCED:
            kept.append(x)
    findings=kept
    result["rendered_counts"]=rendered_counts
    result["status"]="FOUND" if findings else "NOT_FOUND"
    result["findings"]=findings
    result["advisories"]=advisories
    result["finding_count"]=len(findings)
    result["advisory_count"]=len(advisories)
    result["limitations"]=a["limitations"]
    result["complete"]=a["complete"] and b["complete"]
    return result

def main():
    ds=domains()
    os.makedirs(OUT,exist_ok=True)
    stamp=time.strftime("%Y%m%dT%H%M%SZ",time.gmtime())
    results=[]
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futures={ex.submit(scan_one,d):d for d in ds}
        for fut in as_completed(futures):
            d=futures[fut]
            try:r=fut.result()
            except Exception as e:r={"domain":d,"status":"ERROR","error":type(e).__name__+": "+str(e)}
            results.append(r)
            print(f"[{r.get('status','ERROR'):<22}] {d} findings={r.get('finding_count',0)} rendered={r.get('rendered_counts',{})}")
    results.sort(key=lambda x:x["domain"])
    jsonl=os.path.join(OUT,f"scan_{stamp}.jsonl")
    csvp=os.path.join(OUT,f"scan_{stamp}.csv")
    with open(jsonl,"w") as f:
        for r in results:f.write(json.dumps(r,separators=(",",":"))+"\n")
    with open(csvp,"w",newline="") as f:
        fields=["domain","status","http_status","finding_count","advisory_count",
                "rendered_confirmed","rendered_not_reproduced","rendered_error",
                "rendered_verifier","shopify_confidence","market","error"]
        w=csv.DictWriter(f,fieldnames=fields); w.writeheader()
        for r in results:
            rc=r.get("rendered_counts",{})
            w.writerow({"domain":r["domain"],"status":r.get("status"),
                        "http_status":r.get("http_status"),
                        "finding_count":r.get("finding_count",0),
                        "advisory_count":r.get("advisory_count",0),
                        "rendered_confirmed":rc.get("CONFIRMED",0),
                        "rendered_not_reproduced":rc.get("NOT_REPRODUCED",0),
                        "rendered_error":rc.get("ERROR",0),
                        "rendered_verifier":r.get("rendered_verifier"),
                        "shopify_confidence":(r.get("shopify") or {}).get("confidence"),
                        "market":r.get("market"),"error":r.get("error")})
    print(f"completed {len(results)} domains -> {jsonl} and {csvp}")

if __name__=="__main__":
    main()
