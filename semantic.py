"""Evidence-backed semantic inference for A11yForge.

The engine deliberately separates inference from mutation. It only auto-applies a semantic
repair when the source contains a strong, deterministic signal for the intended meaning.
Everything else becomes a review proposal with the evidence that led to the suggestion.
"""
from html import escape
import re
from urllib.parse import urlsplit
from dom import Tree, walk, ws

SAFE = "SAFE_AUTO_REPAIR"
REVIEW = "REVIEW_REQUIRED"
UNREPAIRABLE = "UNREPAIRABLE_WITHOUT_SEMANTIC_INPUT"

ROUTE_NAMES = {
    "cart": "Cart", "basket": "Cart", "bag": "Shopping bag",
    "search": "Search", "account": "Account", "login": "Log in", "signin": "Sign in",
    "logout": "Log out", "menu": "Menu", "wishlist": "Wishlist", "favorites": "Favorites",
    "favourites": "Favourites", "checkout": "Checkout", "close": "Close",
    "next": "Next", "previous": "Previous", "prev": "Previous",
    "play": "Play", "pause": "Pause", "mute": "Mute", "unmute": "Unmute",
    "increase": "Increase quantity", "decrease": "Decrease quantity",
    "remove": "Remove", "delete": "Delete", "clear": "Clear", "submit": "Submit",
    "sort": "Sort", "filter": "Filter", "compare": "Compare", "share": "Share",
    "add-to-cart": "Add to cart", "add_to_cart": "Add to cart",
    "quick-add": "Quick add", "quick_add": "Quick add",
    "add-to-wishlist": "Add to wishlist", "add_to_wishlist": "Add to wishlist",
}

FIELD_NAMES = {
    "email": "Email", "email-address": "Email", "e-mail": "Email",
    "tel": "Phone", "phone": "Phone", "telephone": "Phone",
    "first-name": "First name", "firstname": "First name", "given-name": "First name",
    "last-name": "Last name", "lastname": "Last name", "family-name": "Last name",
    "name": "Name", "full-name": "Full name", "fullname": "Full name",
    "address": "Address", "street-address": "Street address",
    "address-line1": "Address line 1", "address-line2": "Address line 2",
    "city": "City", "country": "Country", "postal-code": "Postal code",
    "zip": "ZIP code", "zip-code": "ZIP code", "state": "State", "province": "Province",
    "search": "Search", "query": "Search", "q": "Search",
    "password": "Password", "new-password": "New password", "current-password": "Current password",
    "username": "Username", "user": "Username", "company": "Company",
}

PROVIDER_IFRAME_NAMES = (
    ("youtube.com", "YouTube video"), ("youtube-nocookie.com", "YouTube video"),
    ("youtu.be", "YouTube video"), ("vimeo.com", "Vimeo video"),
    ("maps.google.", "Google map"), ("google.com/maps", "Google map"),
    ("googleusercontent.com/maps", "Google map"), ("spotify.com", "Spotify player"),
    ("soundcloud.com", "SoundCloud player"), ("instagram.com", "Instagram content"),
)

def _clean(value):
    return re.sub(r"\s+", " ", value or "").strip()

def _attr(tag, name):
    m = re.search(rf"""\\b{re.escape(name)}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'=<>]+))""", tag, re.I)
    return _clean(next((g for g in m.groups() if g is not None), "")) if m else ""

def _replace_or_add(tag, name, value):
    pat = re.compile(rf"""\s{re.escape(name)}\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'=<>]+)""", re.I)
    replacement = f' {name}="{escape(value, quote=True)}"'
    if pat.search(tag):
        return pat.sub(replacement, tag, count=1)
    return tag[:-1] + replacement + ">"

def _node_at(tree, offset):
    best = None
    for n in walk(tree.root):
        if n.off <= offset and (best is None or n.off >= best.off):
            best = n
    return best

def _text(n):
    if n is None:
        return ""
    parts = list(n.text)
    for c in n.children:
        parts.append(_text(c))
    return _clean(" ".join(parts))

def _ancestors(n):
    out = []
    while n is not None:
        out.append(n)
        n = n.parent
    return out

def _token(value):
    value = re.sub(r"([a-z])([A-Z])", r"\1-\2", value or "")
    value = re.sub(r"[^a-zA-Z0-9]+", "-", value).strip("-").lower()
    return value

def _semantic_token(node):
    for key in ("data-action", "data-testid", "data-test", "data-name", "name", "id"):
        value = _token(node.attrs.get(key, ""))
        if value:
            for token, label in ROUTE_NAMES.items():
                if token in value:
                    return label, key, value
    return None

def _nearest_heading(node):
    for a in _ancestors(node)[1:]:
        for c in a.children:
            if c.tag in ("h1", "h2", "h3", "h4", "h5", "h6"):
                t = _text(c)
                if t and len(t) <= 120:
                    return t
    return None

def _figure_caption(node):
    for a in _ancestors(node):
        if a.tag == "figure":
            caps = [c for c in a.children if c.tag == "figcaption"]
            if len(caps) == 1:
                t = _text(caps[0])
                if 1 <= len(t) <= 160:
                    return t
    return None

def _route_label(node):
    href = node.attrs.get("href", "")
    path = urlsplit(href).path.lower()
    parts = [p for p in path.split("/") if p]
    for p in reversed(parts):
        p = _token(p)
        if p in ROUTE_NAMES:
            return ROUTE_NAMES[p]
    query = (href.split("?", 1)[1] if "?" in href else "").lower()
    for token, label in ROUTE_NAMES.items():
        if re.search(rf"(?:^|[=&_-]){re.escape(token)}(?:$|[=&_-])", query):
            return label
    return None

def _field_label(node):
    for key in ("autocomplete", "name", "id", "data-field", "data-name"):
        raw = _token(node.attrs.get(key, ""))
        if raw in FIELD_NAMES:
            return FIELD_NAMES[raw], key, raw
        for token, label in FIELD_NAMES.items():
            if raw == token or raw.endswith("-" + token):
                return label, key, raw
    return None

def _iframe_label(node):
    src = node.attrs.get("src", "").lower()
    for needle, label in PROVIDER_IFRAME_NAMES:
        if needle in src:
            return label, "src", needle
    return None

def infer(source, finding):
    """Return a semantic repair proposal without mutating source.

    The returned object always contains confidence, evidence and a reason. SAFE_AUTO_REPAIR
    is reserved for signals whose meaning is directly encoded in the markup.
    """
    rule = finding.get("base_rule") or finding.get("rule", "")
    off = int(finding.get("off", 0))
    tree = Tree(source)
    node = _node_at(tree, off)
    if node is None:
        return {"confidence": REVIEW, "reason": "source node could not be resolved", "evidence": []}

    if rule == "image-alt":
        role = node.attrs.get("role", "").strip().lower()
        if node.attrs.get("aria-hidden", "").strip().lower() == "true" or role in ("presentation", "none"):
            return {"confidence": SAFE_AUTO_REPAIR, "value": "", "attribute": "alt",
                    "reason": "markup explicitly declares the image decorative",
                    "evidence": ["aria-hidden=true" if node.attrs.get("aria-hidden", "").strip().lower() == "true" else f"role={role}"]}
        explicit = _figure_caption(node)
        if explicit:
            return {"confidence": SAFE_AUTO_REPAIR, "value": explicit,
                    "attribute": "alt", "reason": "single figcaption is the image's explicit nearby text alternative",
                    "evidence": ["figure/figcaption"]}
        return {"confidence": UNREPAIRABLE, "reason": "image meaning is not explicit enough to infer safely",
                "evidence": ["no authoritative alt source"]}

    if rule == "link-name":
        label = _route_label(node)
        if label:
            return {"confidence": SAFE_AUTO_REPAIR, "value": label, "attribute": "aria-label",
                    "reason": "destination route deterministically identifies the link action",
                    "evidence": ["href route"]}
        token = _semantic_token(node)
        if token:
            return {"confidence": REVIEW, "value": token[0], "attribute": "aria-label",
                    "reason": "data/name token suggests intent but is not user-facing copy",
                    "evidence": [f"{token[1]}={token[2]}"]}
        return {"confidence": UNREPAIRABLE, "reason": "link purpose is not explicit enough to invent a name",
                "evidence": ["no route or semantic action token"]}

    if rule == "button-name":
        token = _semantic_token(node)
        if token:
            return {"confidence": SAFE_AUTO_REPAIR, "value": token[0], "attribute": "aria-label",
                    "reason": "explicit action token maps to a deterministic UI action",
                    "evidence": [f"{token[1]}={token[2]}"]}
        return {"confidence": UNREPAIRABLE, "reason": "button intent is not explicit enough to invent copy",
                "evidence": ["no deterministic action token"]}

    if rule == "label":
        label = _field_label(node)
        if label:
            return {"confidence": SAFE_AUTO_REPAIR, "value": label[0], "attribute": "aria-label",
                    "reason": "standard form-field token identifies the control purpose",
                    "evidence": [f"{label[1]}={label[2]}"]}
        return {"confidence": UNREPAIRABLE, "reason": "control purpose requires an authoritative visible label or semantic input",
                "evidence": ["no standard field token"]}

    if rule == "frame-title":
        label = _iframe_label(node)
        if label:
            return {"confidence": SAFE_AUTO_REPAIR, "value": label[0], "attribute": "title",
                    "reason": "iframe source identifies a known embedded service",
                    "evidence": [f"src contains {label[2]}"]}
        return {"confidence": UNREPAIRABLE, "reason": "embedded content purpose is not safely inferable",
                "evidence": ["unknown iframe source"]}

    if rule == "html-has-lang":
        locale = ""
        for n in walk(tree.root):
            if n.tag == "meta" and n.attrs.get("property", "").lower() == "og:locale":
                locale = _clean(n.attrs.get("content", ""))
                break
        if locale:
            value = locale.replace("_", "-")
            language = value.split("-", 1)[0].lower()
            if re.fullmatch(r"[a-z]{2,3}(?:-[A-Za-z0-9]{2,8})?", value):
                return {"confidence": SAFE_AUTO_REPAIR, "value": value, "attribute": "lang",
                        "reason": "og:locale explicitly declares the document locale",
                        "evidence": [f"og:locale={locale}"]}
            if re.fullmatch(r"[a-z]{2,3}", language):
                return {"confidence": REVIEW, "value": language, "attribute": "lang",
                        "reason": "locale provides a language but not a complete locale",
                        "evidence": [f"og:locale={locale}"]}
        return {"confidence": UNREPAIRABLE, "reason": "document language is not authoritative in the source",
                "evidence": ["no valid og:locale"]}

    if rule == "document-title":
        for n in walk(tree.root):
            if n.tag == "meta" and n.attrs.get("property", "").lower() == "og:site_name":
                value = _clean(n.attrs.get("content", ""))
                if value:
                    return {"confidence": REVIEW, "value": value, "attribute": "title",
                            "reason": "site name is available but is not necessarily the page title",
                            "evidence": ["og:site_name"]}
        heading = _nearest_heading(node)
        if heading:
            return {"confidence": REVIEW, "value": heading, "attribute": "title",
                    "reason": "nearest heading is plausible page context but not authoritative title metadata",
                    "evidence": ["nearest heading"]}
        return {"confidence": UNREPAIRABLE, "reason": "no authoritative page-title source",
                "evidence": ["no og:site_name or heading"]}

    return {"confidence": REVIEW, "reason": "rule has no semantic inference strategy", "evidence": []}

def apply_semantic(source, finding, proposal):
    """Apply one already-approved semantic proposal at the finding offset."""
    if proposal.get("confidence") != SAFE_AUTO_REPAIR or proposal.get("value") is None:
        return source, False
    off = int(finding.get("off", -1))
    raw = finding.get("snippet", "")
    if off < 0 or off >= len(source):
        return source, False
    end = min(len(source), off + max(int(finding.get("length", 0)), len(raw), 1))
    tag = source[off:end]
    if not tag.lstrip().startswith("<") or ">" not in tag:
        return source, False
    fixed = _replace_or_add(tag, proposal["attribute"], proposal["value"])
    if fixed == tag:
        return source, False
    return source[:off] + fixed + source[end:], True
