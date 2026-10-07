"""shopscan.fetch -- polite, bounded HTTP."""
import ipaddress, os, re, socket, threading, time, urllib.error, urllib.request, urllib.robotparser, zlib
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
ROBOT_TOKEN="a11yforge"; CONTACT=os.getenv("SHOPSCAN_CONTACT","").strip(); UA="a11yforge/1.7 (+accessibility triage)" + (f" contact: {CONTACT}" if CONTACT else "")
RETRIES=2; MAX_REDIRECTS=5; RETRY_AFTER_CAP=10.0; CRAWL_DELAY_CAP=30.0
TRANSIENT={429,500,502,503,504}

def _public_ip(value):
    try:
        ip=ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_global and not ip.is_multicast and not ip.is_unspecified

def is_public_url(url):
    try:
        p=urlsplit(url.strip())
        if p.scheme.lower() not in ("http","https") or not p.hostname or p.username or p.password:
            return False
        host=p.hostname.rstrip(".").lower()
        if host in {"localhost","metadata.google.internal","metadata.amazonaws.com"} or host.endswith(".localhost"):
            return False
        try:
            return _public_ip(ipaddress.ip_address(host))
        except ValueError:
            pass
        infos=socket.getaddrinfo(host,p.port or (443 if p.scheme.lower()=="https" else 80),type=socket.SOCK_STREAM)
        ips={item[4][0] for item in infos}
        return bool(ips) and all(_public_ip(ip) for ip in ips)
    except (ValueError,socket.gaierror,OSError):
        return False
TRACKING=re.compile(r"^(utm_.*|fbclid|gclid|msclkid|mc_cid|mc_eid|ref|_pos|_sid|_ss|_psq|_fid|_v|srsltid|igshid)$",re.I)
def canonical_url(url):
    p=urlsplit(url.strip()); host=(p.hostname or "").lower()
    port=f":{p.port}" if p.port and not ((p.scheme=="http" and p.port==80) or (p.scheme=="https" and p.port==443)) else ""
    q=urlencode(sorted((k,v) for k,v in parse_qsl(p.query,keep_blank_values=True) if not TRACKING.match(k)))
    path=p.path or "/"
    if len(path)>1 and path.endswith("/"):path=path[:-1]
    return urlunsplit((p.scheme.lower(),host+port,path,q,""))
class _Redirects(urllib.request.HTTPRedirectHandler):
    def __init__(self,chain):self.chain=chain
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        if len(self.chain)>=MAX_REDIRECTS:raise urllib.error.HTTPError(req.full_url,code,"too many redirects",headers,fp)
        if not newurl.lower().startswith(("http://","https://")) or not is_public_url(newurl):raise urllib.error.HTTPError(req.full_url,code,"unsafe redirect",headers,fp)
        self.chain.append((code,newurl));return super().redirect_request(req,fp,code,msg,headers,newurl)
def decode_body(body,header_charset=None):
    if body.startswith(b"\xef\xbb\xbf"):return body[3:].decode("utf-8","replace"),"utf-8","bom",0
    if body.startswith((b"\xff\xfe",b"\xfe\xff")):return body.decode("utf-16","replace"),"utf-16","bom",0
    if header_charset:
        try:
            t=body.decode(header_charset,"replace");return t,header_charset,"header",t.count("\ufffd")
        except LookupError:pass
    try:return body.decode("utf-8"),"utf-8","utf8_strict",0
    except UnicodeDecodeError:pass
    m=re.search(rb"<meta[^>]+charset\s*=\s*[\"']?([A-Za-z0-9_\-]+)",body[:4096],re.I)
    if m:
        try:
            name=m.group(1).decode("ascii");t=body.decode(name,"replace");return t,name.lower(),"meta",t.count("\ufffd")
        except LookupError:pass
    t=body.decode("cp1252","replace");return t,"cp1252","fallback_cp1252",t.count("\ufffd")
class Fetcher:
    def __init__(self,scheme="https",delay=2.0,timeout=15,max_bytes=3_000_000,ua=UA,retries=RETRIES,backoff=(0.5,1.5),retry_after_cap=RETRY_AFTER_CAP):
        self.scheme,self.delay,self.timeout,self.max_bytes,self.ua=scheme,delay,timeout,max_bytes,ua;self.retries,self.backoff,self.retry_after_cap=retries,backoff,retry_after_cap
        self.last,self.robots,self.host_delay,self.broken={}, {}, {}, set();self.lock=threading.Lock();self.requests_made=0
    def _wait(self,host):
        with self.lock:
            now=time.time();gap=max(self.delay,self.host_delay.get(host,0));t=max(now,self.last.get(host,0)+gap);self.last[host]=t
        if t>now:time.sleep(t-now)
    def _once(self,url):
        self._wait(urlsplit(url).netloc);self.requests_made+=1
        req=urllib.request.Request(url,headers={"User-Agent":self.ua,"Accept":"text/html,*/*;q=0.5","Accept-Encoding":"gzip, deflate"});chain=[];opener=urllib.request.build_opener(_Redirects(chain));t0=time.time()
        try:
            with opener.open(req,timeout=self.timeout) as r:
                wire=r.read(self.max_bytes+1);hdrs={k.lower():v for k,v in r.headers.items()};status,final=r.status,r.geturl();charset=r.headers.get_content_charset()
        except urllib.error.HTTPError as e:return {"status":e.code,"final":url,"body":b"","headers":{k.lower():v for k,v in (e.headers or {}).items()},"chain":[],"error":None,"elapsed":time.time()-t0}
        except Exception as e:return {"status":0,"final":url,"body":b"","headers":{},"chain":[],"error":type(e).__name__+": "+str(e)[:100],"elapsed":time.time()-t0}
        truncated=len(wire)>self.max_bytes;body=wire[:self.max_bytes];enc=hdrs.get("content-encoding","").lower()
        if enc in ("gzip","deflate","x-gzip"):
            d=zlib.decompressobj(16+zlib.MAX_WBITS if "gzip" in enc else zlib.MAX_WBITS)
            try:
                out=d.decompress(body,self.max_bytes+1)
                if len(out)>self.max_bytes or d.unconsumed_tail:truncated=True
                body=out[:self.max_bytes]
            except zlib.error as e:return {"status":status,"final":final,"body":b"","headers":hdrs,"chain":chain or [],"error":"bad_encoding: "+str(e)[:60],"elapsed":time.time()-t0}
        return {"status":status,"final":final,"body":body,"headers":hdrs,"chain":chain,"error":None,"truncated":truncated,"charset":charset,"elapsed":time.time()-t0}
    def raw(self,url):
        host=urlsplit(url).netloc
        if host in self.broken:return self._result({"status":429,"final":url,"body":b"","headers":{},"chain":[],"error":"host circuit-broken after repeated 429"},0)
        r=None
        for attempt in range(self.retries+1):
            r=self._once(url)
            if r["status"] not in TRANSIENT and r["status"]!=0:break
            if attempt==self.retries:break
            ra=r["headers"].get("retry-after","");wait=min(float(ra),self.retry_after_cap) if ra.strip().isdigit() else self.backoff[min(attempt,len(self.backoff)-1)]
            time.sleep(max(0.0,wait))
        if r["status"]==429:self.broken.add(host)
        return self._result(r,attempt+1)
    def _result(self,r,attempts):
        status,body=r["status"],r.get("body",b"");state="OK";ctype=r["headers"].get("content-type","").lower()
        if status in (403,429):state="BLOCKED"
        elif status==0 or status>=500 or r.get("error") or status in (401,404,410) or not (200<=status<300):state="ERROR"
        elif ctype and not any(x in ctype for x in ("html","xml","text/plain")):state="NON_HTML"
        return {"state":state,"status":status,"final":r["final"],"body":body,"headers":r["headers"],"redirects":r.get("chain",[]),"bytes_received":len(body),"max_bytes":self.max_bytes,"truncated":bool(r.get("truncated")),"charset":r.get("charset"),"error":r.get("error"),"attempts":attempts,"elapsed":round(r.get("elapsed",0),3)}
    def _robots_for(self,origin):
        rp=self.robots.get(origin)
        if rp is None:
            rp=urllib.robotparser.RobotFileParser();r=self.raw(origin+"/robots.txt")
            if r["status"]==200:
                try:rp.parse(r["body"].decode("utf-8","replace").splitlines())
                except Exception:rp.parse([])
            elif 400<=r["status"]<500 and r["status"]!=429:rp.parse([])
            else:rp.parse(["User-agent: *","Disallow: /"])
            cd=rp.crawl_delay(ROBOT_TOKEN)
            if cd:self.host_delay[urlsplit(origin).netloc]=min(float(cd),CRAWL_DELAY_CAP)
            self.robots[origin]=rp
        return rp
    def allowed(self,url):
        p=urlsplit(url);return self._robots_for(f"{p.scheme}://{p.netloc}").can_fetch(ROBOT_TOKEN,url)
    def page(self,url):
        if not is_public_url(url):
            return {"state":"UNSAFE_URL","status":0,"final":url,"body":b"","headers":{},"redirects":[],"bytes_received":0,"max_bytes":self.max_bytes,"truncated":False,"charset":None,"error":"destination is not globally routable","attempts":0,"elapsed":0}
        if not self.allowed(url):return {"state":"ROBOTS","status":-1,"final":url,"body":b"","headers":{},"redirects":[],"bytes_received":0,"max_bytes":self.max_bytes,"truncated":False,"charset":None,"error":"robots.txt disallows","attempts":0,"elapsed":0}
        return self.raw(url)
