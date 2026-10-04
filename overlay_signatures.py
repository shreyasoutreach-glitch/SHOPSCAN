"""Runtime and source-level accessibility overlay signatures.

Detection is evidence-based. A vendor is reported only when its signature is observed.
This registry is intentionally extensible and never claims exhaustive vendor coverage.
"""

OVERLAY_SIGNATURES = {
    "accessiBe": {
        "domains": ("accessibe.com", "acsbapp.com"),
        "scripts": ("acsbapp", "acsbaccessibility"),
        "iframes": ("acsbapp.com", "accessibe.com"),
        "markers": ("#acsb-trigger", "[data-acsb]", ".acsb-trigger"),
    },
    "UserWay": {
        "domains": ("userway.org", "userwaycdn.com"),
        "scripts": ("userway", "userwaycdn"),
        "iframes": ("userway.org",),
        "markers": ("#userway", "[data-userway]", ".uwy"),
    },
    "AudioEye": {
        "domains": ("audioeye.com",),
        "scripts": ("audioeye",),
        "iframes": ("audioeye.com",),
        "markers": ("[data-audioeye]", "#audioeye", ".ae-widget"),
    },
    "EqualWeb": {
        "domains": ("equalweb.com", "nagich.com"),
        "scripts": ("equalweb", "nagich"),
        "iframes": ("equalweb.com",),
        "markers": ("#INDmenu-btn", "[data-equalweb]", ".ind-widget"),
    },
    "Level Access": {
        "domains": ("levelaccess.net",),
        "scripts": ("levelaccess",),
        "iframes": ("levelaccess.net",),
        "markers": ("[data-levelaccess]", "#levelaccess"),
    },
    "AccessiWay": {
        "domains": ("accessiway.com",),
        "scripts": ("accessiway",),
        "iframes": ("accessiway.com",),
        "markers": ("[data-accessiway]", "#accessiway"),
    },
}

def _signals(blob, signature):
    blob=(blob or "").lower()
    hits=[]
    for family in ("domains","scripts","iframes","markers"):
        for token in signature.get(family,()):
            if token.lower() in blob:
                hits.append(f"{family}:{token}")
    return sorted(set(hits))

def detect_source_overlays(*, script_urls=(), iframe_urls=(), markers=(), globals=()):
    blob=" ".join([*script_urls,*iframe_urls,*markers,*globals]).lower()
    result=[]
    for vendor, sig in OVERLAY_SIGNATURES.items():
        hits=_signals(blob,sig)
        if hits:
            result.append({"vendor":vendor,"confidence":"HIGH" if len(hits)>=2 else "MEDIUM",
                           "signals":hits[:12],"source_observed":True,"runtime_observed":False})
    return result
