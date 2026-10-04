"""Bounded same-origin page discovery for A11yForge.

Discovery is read-only. It never clicks, submits, mutates, or follows off-site links.
"""
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urldefrag
from fetch import is_public_url

class _Links(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links=[]
    def handle_starttag(self,tag,attrs):
        if tag.lower()!="a": return
        href=dict(attrs).get("href")
        if href: self.links.append(href)

def discover(start_url, html, max_pages=4):
    base=urlsplit(start_url)
    root_host=(base.hostname or "").lower()
    parser=_Links()
    try: parser.feed(html)
    except Exception: return [start_url]
    candidates=[]
    for href in parser.links:
        absolute=urldefrag(urljoin(start_url,href))[0]
        p=urlsplit(absolute)
        if p.scheme not in ("http","https") or not p.hostname: continue
        if p.hostname.lower()!=root_host: continue
        if not is_public_url(absolute): continue
        if any(x in p.path.lower() for x in ("/account","/checkout","/cart","/logout")):
            continue
        candidates.append(absolute)
    def score(u):
        path=urlsplit(u).path.lower()
        if any(x in path for x in ("/products/","/product/")): return 0
        if any(x in path for x in ("/collections/","/collection/")): return 1
        if any(x in path for x in ("/search","/pages/")): return 2
        return 3
    unique=[]
    seen={start_url}
    for u in sorted(set(candidates),key=score):
        if u not in seen:
            seen.add(u); unique.append(u)
        if len(unique)+1>=max_pages: break
    return [start_url]+unique
