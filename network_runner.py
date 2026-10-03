"""Network execution wrapper for ShopScan 1.1.

Runs the original static analysis against public storefronts. It does not claim legal compliance,
does not bypass robots.txt, and records blocked/error states instead of inventing findings.
"""
import csv,json,os,time
from concurrent.futures import ThreadPoolExecutor,as_completed
from urllib.parse import urljoin
from fetch import Fetcher,canonical_url,decode_body
from scan import analyze,SCANNER_VERSION

DOMAINS_FILE=os.getenv("SHOPSCAN_DOMAINS","network_domains.txt")
OUT=os.getenv("SHOPSCAN_OUT","out")
WORKERS=max(1,min(int(os.getenv("SHOPSCAN_WORKERS","4")),8))
DELAY=float(os.getenv("SHOPSCAN_DELAY","2"))
MAX_BYTES=int(os.getenv("SHOPSCAN_MAX_BYTES","3000000"))

def domains():
    with open(DOMAINS_FILE) as f:
        return list(dict.fromkeys(x.strip().lower().replace("https://","").replace("http://","").strip("/") for x in f if x.strip() and not x.lstrip().startswith("#")))

def scan_one(domain):
    f=Fetcher(delay=DELAY,max_bytes=MAX_BYTES)
    home=canonical_url("https://"+domain+"/")
    first=f.page(home)
    result={"domain":domain,"scanner_version":SCANNER_VERSION,"scanned_at":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
            "url":home,"status":first["state"],"http_status":first["status"],"error":first.get("error"),
            "shopify":None,"market":None,"findings":[],"advisories":[],"verified_loads":0}
    if first["state"]!="OK": return result
    text,enc,method,repl=decode_body(first["body"],first.get("charset"))
    a=analyze(text,first["final"],first.get("headers"))
    result["encoding"]={"name":enc,"method":method,"replacement_chars":repl}
    result["shopify"]=a["context"]["platform"];result["market"]=a["context"]["market_label"]
    if a["context"]["platform"]["platform"]!="shopify":
        result["status"]="SKIPPED" if a["context"]["platform"]["platform"]=="not_detected" else "UNKNOWN"
        result["reason"]="no Shopify evidence" if result["status"]=="SKIPPED" else "possible Shopify only"
        return result
    second=f.page(home)
    if second["state"]!="OK": result["status"]="UNVERIFIED_SECOND_LOAD";result["error"]=second.get("error");return result
    text2,_,_,_=decode_body(second["body"],second.get("charset"));b=analyze(text2,second["final"],second.get("headers"))
    result["verified_loads"]=2
    keys={(x["signature"],x["occurrence"]) for x in b["findings"]}
    findings=[x for x in a["findings"] if (x["signature"],x["occurrence"]) in keys]
    advkeys={(x["signature"],x["occurrence"]) for x in b["advisories"]}
    advisories=[x for x in a["advisories"] if (x["signature"],x["occurrence"]) in advkeys]
    result["status"]="FOUND" if findings else "NOT_FOUND"
    result["findings"]=findings;result["advisories"]=advisories
    result["finding_count"]=len(findings);result["advisory_count"]=len(advisories)
    result["limitations"]=a["limitations"];result["complete"]=a["complete"] and b["complete"]
    return result

def main():
    ds=domains();os.makedirs(OUT,exist_ok=True);stamp=time.strftime("%Y%m%dT%H%M%SZ",time.gmtime())
    results=[]
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futures={ex.submit(scan_one,d):d for d in ds}
        for fut in as_completed(futures):
            d=futures[fut]
            try:r=fut.result()
            except Exception as e:r={"domain":d,"status":"ERROR","error":type(e).__name__+": "+str(e)}
            results.append(r);print(f"[{r.get('status','ERROR'):<22}] {d} findings={r.get('finding_count',0)}")
    results.sort(key=lambda x:x["domain"])
    jsonl=os.path.join(OUT,f"scan_{stamp}.jsonl")
    csvp=os.path.join(OUT,f"scan_{stamp}.csv")
    with open(jsonl,"w") as f:
        for r in results:f.write(json.dumps(r,separators=(",",":"))+"\n")
    with open(csvp,"w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=["domain","status","http_status","finding_count","advisory_count","shopify_confidence","market","error"])
        w.writeheader()
        for r in results:w.writerow({"domain":r["domain"],"status":r.get("status"),"http_status":r.get("http_status"),"finding_count":r.get("finding_count",0),
                                     "advisory_count":r.get("advisory_count",0),"shopify_confidence":(r.get("shopify") or {}).get("confidence"),
                                     "market":r.get("market"),"error":r.get("error")})
    print(f"completed {len(results)} domains -> {jsonl} and {csvp}")

if __name__=="__main__": main()
