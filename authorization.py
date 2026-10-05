"""Consent-first domain authorization for A11yForge.

Authorization is explicit. A domain is not considered authorized merely because it is public.
"""
import hashlib
import re
import secrets
from html.parser import HTMLParser
from urllib.parse import urlsplit

NOT_REQUESTED="NOT_REQUESTED"
REQUESTED="REQUESTED"
GRANTED="GRANTED"
DECLINED="DECLINED"
VERIFICATION_META="a11yforge-verification"
DNS_PREFIX="_a11yforge-verification"

try:
    import dns.resolver
except ImportError:
    dns=None

class _MetaParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tokens=[]
    def handle_starttag(self,tag,attrs):
        if tag.lower()!="meta": return
        a={k.lower():(v or "") for k,v in attrs}
        if a.get("name","").strip().lower()==VERIFICATION_META:
            self.tokens.append(a.get("content","").strip())

def normalize_domain(value):
    raw=(value or "").strip()
    if "://" not in raw:
        raw="https://"+raw
    p=urlsplit(raw)
    host=(p.hostname or "").strip().rstrip(".").lower()
    if not host or p.username or p.password or p.port:
        raise ValueError("Enter a domain without credentials or a custom port.")
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?",host,re.I):
        raise ValueError("Enter a valid domain name.")
    return host

def issue_token():
    return "af1_"+secrets.token_urlsafe(24)

def token_digest(token):
    return hashlib.sha256((token or "").encode()).hexdigest()

def instructions(domain,token):
    return {
        "dns_name": f"{DNS_PREFIX}.{domain}",
        "dns_value": token,
        "meta_tag": f'<meta name="{VERIFICATION_META}" content="{token}">',
        "note":"Publish the token in DNS TXT or the storefront homepage meta tag, then verify ownership.",
    }

def _meta_verified(body,token):
    parser=_MetaParser()
    try:
        parser.feed(body)
    except Exception:
        return False
    return token in parser.tokens

def _dns_verified(domain,token):
    if dns is None:
        return False
    try:
        answer=dns.resolver.resolve(f"{DNS_PREFIX}.{domain}","TXT",lifetime=3)
        values=[]
        for record in answer:
            values.extend(str(x,"utf-8") if isinstance(x,bytes) else str(x) for x in getattr(record,"strings",()))
            if not getattr(record,"strings",None):
                values.append(str(record).strip('"'))
        return token in values
    except Exception:
        return False

def verify(domain,token,fetcher):
    domain=normalize_domain(domain)
    url=f"https://{domain}/"
    page=fetcher.page(url)
    meta=False
    if page.get("state")=="OK":
        body=page["body"].decode(page.get("charset") or "utf-8","replace")
        meta=_meta_verified(body,token)
    dns_ok=_dns_verified(domain,token)
    method="dns_txt" if dns_ok else "meta_tag" if meta else None
    return {"granted":bool(method),"method":method,"domain":domain,"url":page.get("final") or url,
            "fetch_state":page.get("state"),"dns_available":dns is not None}
