"""shopscan.shopify -- platform detection and market signals expressed as evidence + confidence."""
import re
from urllib.parse import urlsplit
SHOPIFY_THRESHOLD=0.75
POSSIBLE_THRESHOLD=0.40
PLATFORM_SIGNALS={"header_shopify":(0.80,True),"meta_checkout_token":(0.65,True),"global_object":(0.60,True),
"asset_pattern":(0.45,True),"cdn_host":(0.40,False),"myshopify_ref":(0.35,True),"shopifycloud":(0.30,False),"storefront_paths":(0.10,False)}
_HEADER_NAMES=("x-shopid","x-shopify-stage","x-sorting-hat-shopid")
_URL_ATTRS=("src","href","srcset","data-src","content","action")
def _noisy_or(ws):
    p=1.0
    for w in ws:p*=1-w
    return round(1-p,4)
def collect(nodes):
    urls=[]; scripts=[]
    for n in nodes:
        for a in _URL_ATTRS:
            v=n.attrs.get(a)
            if v: urls.append(v)
        if n.tag=="script" and n.text:scripts.append("".join(n.text))
    return urls,"\n".join(scripts)
def detect_platform(nodes,headers=None):
    urls,scripts=collect(nodes); sig=set(); hosts_paths=[]
    for u in urls:
        try:p=urlsplit(u.split()[0] if " " in u.strip() else u.strip())
        except ValueError:continue
        hosts_paths.append((p.netloc.lower(),p.path))
    if any(h=="cdn.shopify.com" for h,_ in hosts_paths):sig.add("cdn_host")
    if any(pa.startswith(("/cdn/shop/","/cdn/shopifycloud/")) or "/cdn/shop/" in pa for _,pa in hosts_paths):sig.add("asset_pattern")
    if any(h.endswith(".myshopify.com") for h,_ in hosts_paths) or re.search(r"[a-z0-9-]+\.myshopify\.com",scripts):sig.add("myshopify_ref")
    if any("shopifycloud" in h or "shopifycloud" in pa for h,pa in hosts_paths) or "shopifycloud" in scripts:sig.add("shopifycloud")
    if re.search(r"\bShopify\.(shop|theme|currency|country|locale)\b|window\.Shopify\b",scripts):sig.add("global_object")
    for n in nodes:
        if n.tag=="meta" and n.attrs.get("name","").strip().lower() in ("shopify-checkout-api-token","shopify-digital-wallet"):sig.add("meta_checkout_token");break
    hrefs=[n.attrs["href"] for n in nodes if n.tag=="a" and "href" in n.attrs]
    if sum("/products/" in h for h in hrefs)>=3 and sum("/collections/" in h for h in hrefs)>=1:sig.add("storefront_paths")
    if headers and any(h in headers for h in _HEADER_NAMES):sig.add("header_shopify")
    conf=_noisy_or(PLATFORM_SIGNALS[s][0] for s in sig); first_party=any(PLATFORM_SIGNALS[s][1] for s in sig)
    decision="shopify" if conf>=SHOPIFY_THRESHOLD and first_party else "possible" if conf>=POSSIBLE_THRESHOLD else "not_detected"
    return {"platform":decision,"confidence":conf,"signals":sorted(sig),"threshold":SHOPIFY_THRESHOLD,"first_party_signal":first_party}
MARKET_WEIGHTS={"usd_currency":0.35,"us_country_signal":0.30,"us_contact_signal":0.30,"us_locale_signal":0.20,"us_domain_signal":0.30}
_US_TEL=re.compile(r"^tel:\s*(\+?1[\s.\-(]*\d{3}|\(?\d{3}\)?[\s.\-]\d{3}[\s.\-]\d{4})",re.I)
def market_signals(nodes,host=""):
    _,scripts=collect(nodes)
    m=re.search(r'Shopify\.currency\s*=\s*\{\s*"active"\s*:\s*"([A-Za-z]{3})"',scripts);cur=m.group(1).upper() if m else None
    for n in nodes:
        if n.tag=="meta" and n.attrs.get("property",n.attrs.get("name","")).lower() in ("og:price:currency","product:price:currency"):
            cur=cur or n.attrs.get("content","").strip().upper() or None
    m=re.search(r'Shopify\.country\s*=\s*"([A-Za-z]{2})"',scripts);country=m.group(1).upper() if m else None
    og=next((n.attrs.get("content","") for n in nodes if n.tag=="meta" and n.attrs.get("property")=="og:locale"),"")
    html_n=next((n for n in nodes if n.tag=="html"),None);lang=(html_n.attrs.get("lang","") if html_n else "").strip().lower().replace("_","-")
    tel=any(n.tag=="a" and _US_TEL.match(n.attrs.get("href","").strip()) for n in nodes)
    sig={"usd_currency":cur=="USD","us_country_signal":country=="US","us_contact_signal":tel,
         "us_locale_signal":og.strip().lower().replace("-","_")=="en_us" or lang=="en-us",
         "us_domain_signal":host.lower().split(":")[0].endswith(".us")}
    conf=_noisy_or(MARKET_WEIGHTS[k] for k,v in sig.items() if v);label="high" if conf>=0.60 else "medium" if conf>=0.35 else "low"
    return {"market_signals":sig,"market_confidence":conf,"market_label":label,"currency_active":cur,"country_signal":country,
            "note":"heuristic; currency/country reflect the crawler's vantage point, not proof of where the store sells"}
