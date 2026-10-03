"""shopscan.scan -- precision-first STATIC accessibility rules."""
import re
from hashlib import sha256
from dom import Tree, walk, ws, element_path, stable_signature
from names import build_id_index, name_evidence
from shopify import detect_platform, market_signals, collect

SCANNER_VERSION = "1.3.0"
OBSERVATION = "static_html"
SNIPPET_MAX = 400
RULES = {
    "image-alt": ("image-alt", ["1.1.1"], "A", "critical", "image with no alt attribute"),
    "label": ("label|select-name", ["4.1.2", "1.3.1"], "A", "form field with no accessible label"),
    "button-name": ("button-name", ["4.1.2"], "A", "button with no accessible name"),
    "link-name": ("link-name", ["2.4.4", "4.1.2"], "A", "link with no accessible name"),
    "html-has-lang": ("html-has-lang", ["3.1.1"], "A", "page language not declared"),
    "document-title": ("document-title", ["2.4.2"], "A", "page has no title"),
    "meta-viewport": ("meta-viewport", ["1.4.4"], "AA", "moderate", "zooming disabled in the viewport meta tag"),
    "frame-title": ("frame-title", ["4.1.2"], "A", "serious", "iframe with no title"),
}
IMPACT_POINTS = {"critical": 14, "serious": 9, "moderate": 5}
OVERLAYS = {"accessiBe": ("acsbapp", "accessibe.com"), "UserWay": ("userway.org",), "AudioEye": ("audioeye.com",),
            "EqualWeb": ("equalweb.com", "nagich"), "Level Access widget": ("levelaccess.net/widget",)}

def analyze(src, url="", headers=None):
    tree = Tree(src); nodes = list(walk(tree.root)); index = build_id_index(nodes); labels = {}
    for n in nodes:
        if n.tag == "label" and n.attrs.get("for"): labels.setdefault(n.attrs["for"], []).append(n)
    findings, advisories = [], []; skipped = {"uncertain_visibility": 0, "unknown_name": 0, "provenance_failed": 0}; per_sig = {}
    def record(n, rule, base, ev=None, advisory=False):
        raw = n.raw
        if not raw or src[n.off:n.off + len(raw)] != raw: skipped["provenance_failed"] += 1; return
        sig = stable_signature(rule, n); occ = per_sig.get(sig, 0); per_sig[sig] = occ + 1; ax = RULES[base]
        rec = {"rule": rule, "base_rule": base, "axe": ax[0], "sc": ax[1], "level": ax[2], "impact": ax[3],
               "observation": OBSERVATION, "url": url, "off": n.off, "length": len(raw),
               "snippet": raw[:SNIPPET_MAX], "snippet_truncated": len(raw) > SNIPPET_MAX,
               "context": src[n.off:n.off + 240], "path": element_path(n), "signature": sig, "occurrence": occ,
               "name_evidence": ev, "scanner_version": SCANNER_VERSION, "reproducible_with_axe": not advisory}
        (advisories if advisory else findings).append(rec)
    def judged(n, rule, ev):
        if ev["strength"] == "unknown": skipped["unknown_name"] += 1
        elif ev["strength"] == "strong" or n.hs == "hard": return
        elif n.hs == "uncertain": skipped["uncertain_visibility"] += 1
        elif ev["strength"] == "weak":
            kind = "placeholder-only" if "placeholder" in ev["weak"] and "title" not in ev["weak"] else "title-only"
            record(n, f"advisory:{rule}:{kind}", rule, ev, advisory=True)
        else: record(n, rule, rule, ev)
    for n in nodes:
        t, at = n.tag, n.attrs
        if t == "img" and "alt" not in at: judged(n, "image-alt", name_evidence(n, index, labels, "image"))
        elif t in ("input", "textarea", "select"):
            typ = at.get("type", "text").strip().lower()
            if t == "input" and typ in ("hidden", "submit", "reset", "button", "image"): continue
            judged(n, "label", name_evidence(n, index, labels, "control"))
        elif t == "button": judged(n, "button-name", name_evidence(n, index, labels, "button"))
        elif t == "a" and "href" in at: judged(n, "link-name", name_evidence(n, index, labels, "link"))
        elif t in ("iframe", "frame"): judged(n, "frame-title", name_evidence(n, index, labels, "frame"))
    html_n = next((n for n in nodes if n.tag == "html"), None)
    if html_n is not None:
        if not html_n.attrs.get("lang", "").strip() and not html_n.attrs.get("xml:lang", "").strip(): record(html_n, "html-has-lang", "html-has-lang")
        titles = [n for n in nodes if n.tag == "title" and n.parent is not None and n.parent.tag in ("head", "html")]
        if not titles: record(html_n, "document-title", "document-title")
        elif not "".join(titles[0].text).strip(): record(titles[0], "document-title", "document-title")
    for n in nodes:
        if n.tag == "meta" and n.attrs.get("name", "").strip().lower() == "viewport":
            c = n.attrs.get("content", "").lower(); zoom_off = re.search(r"user-scalable\s*=\s*(no|0)\b", c); m = re.search(r"maximum-scale\s*=\s*([0-9.]+)", c)
            try: capped = m is not None and float(m.group(1)) <= 1.0
            except ValueError: capped = False
            if zoom_off or capped: record(n, "meta-viewport", "meta-viewport")
            break
    host = url.split("//", 1)[-1].split("/", 1)[0] if url else ""; lim = sorted(tree.limitations)
    return {"findings": findings, "advisories": advisories, "skipped": skipped, "limitations": lim,
            "complete": not lim, "context": context(nodes, host, headers),
            "document_hash": sha256(src.encode("utf-8", "replace")).hexdigest(), "node_count": tree.count}

def context(nodes, host="", headers=None):
    urls, scripts = collect(nodes); blob = (" ".join(urls) + " " + scripts).lower()
    ctx = {"platform": detect_platform(nodes, headers), **market_signals(nodes, host)}
    ctx["overlays"] = sorted(k for k, sigs in OVERLAYS.items() if any(s in blob for s in sigs))
    links = [n for n in nodes if n.tag == "a" and "href" in n.attrs]
    ctx["a11y_statement"] = any("accessib" in n.attrs["href"].lower() or "accessib" in "".join(n.text).lower() for n in links)
    ctx["product_links"] = len({n.attrs["href"].split("?")[0] for n in links if "/products/" in n.attrs["href"]})
    ctx["mailtos"] = sorted({n.attrs["href"][7:].split("?")[0].strip().lower() for n in links if n.attrs["href"].lower().startswith("mailto:") and "@" in n.attrs["href"]})[:5]
    t = next((n for n in nodes if n.tag == "title"), None); ctx["title"] = ws("".join(t.text)) if t else ""
    og = next((n for n in nodes if n.tag == "meta" and n.attrs.get("property") == "og:site_name"), None); ctx["site_name"] = og.attrs.get("content", "").strip() if og else ""
    ctx["links"] = [n.attrs["href"] for n in links]; return ctx
