"""Second-generation deterministic accessibility rules.

These rules are deliberately conservative: definite structural/ARIA defects become findings;
heuristic structure concerns remain advisories so the scanner grows without turning noisy.
"""
from dom import stable_signature, ws

RULES = {
    "duplicate-id": ("duplicate-id", ["4.1.2"], "A", "serious", "duplicate id can break programmatic relationships"),
    "aria-reference": ("aria-reference", ["4.1.2"], "A", "serious", "ARIA ID reference does not resolve"),
    "aria-hidden-focusable": ("aria-hidden-focusable", ["4.1.2"], "A", "serious", "focusable content is hidden from assistive technologies"),
    "empty-aria-label": ("empty-aria-label", ["4.1.2"], "A", "serious", "interactive element has an empty aria-label"),
    "positive-tabindex": ("positive-tabindex", ["2.4.3"], "A", "moderate", "positive tabindex can disrupt logical focus order"),
    "heading-order": ("heading-order", ["1.3.1", "2.4.6"], "A", "moderate", "heading hierarchy skips a level"),
}

FOCUSABLE = {"a","button","input","select","textarea","summary","iframe","object","area","audio","video"}

def _text(n):
    return ws(" ".join(n.text))

def _is_focusable(n):
    if "disabled" in n.attrs or n.attrs.get("aria-disabled","").lower()=="true":
        return False
    if n.attrs.get("tabindex") is not None:
        try:
            return int(n.attrs["tabindex"]) >= 0
        except ValueError:
            return False
    if n.tag in FOCUSABLE:
        if n.tag == "a" and "href" not in n.attrs:
            return False
        return True
    return False

def _record(src, n, base, rule, occurrence, evidence=None, advisory=False):
    raw=n.raw
    if not raw or src[n.off:n.off+len(raw)] != raw:
        return None
    ax=RULES[base]
    return {
        "rule": rule, "base_rule": base, "axe": ax[0], "sc": ax[1], "level": ax[2],
        "impact": ax[3], "observation": "static_html", "url": "", "off": n.off,
        "length": len(raw), "snippet": raw[:400], "snippet_truncated": len(raw)>400,
        "context": src[n.off:n.off+240], "path": "", "signature": stable_signature(rule,n),
        "occurrence": occurrence, "name_evidence": evidence or {},
        "scanner_version": "1.6.0", "reproducible_with_axe": not advisory,
    }

def analyze_advanced(src, nodes):
    findings=[]; advisories=[]

    ids={}
    for n in nodes:
        ident=n.attrs.get("id","").strip()
        if ident:
            ids.setdefault(ident,[]).append(n)
    occ={}
    for ident, group in ids.items():
        if len(group)>1:
            for n in group[1:]:
                r=_record(src,n,"duplicate-id","duplicate-id",occ.get("duplicate-id",0),
                          {"id":ident,"count":len(group)})
                occ["duplicate-id"]=occ.get("duplicate-id",0)+1
                if r: findings.append(r)

    valid_ids=set(ids)
    ref_attrs=("aria-labelledby","aria-describedby","aria-owns","aria-activedescendant")
    for n in nodes:
        for attr in ref_attrs:
            raw=n.attrs.get(attr,"").strip()
            if not raw: continue
            refs=raw.split()
            missing=[x for x in refs if x not in valid_ids]
            if missing:
                r=_record(src,n,"aria-reference","aria-reference",occ.get("aria-reference",0),
                          {"attribute":attr,"missing":missing})
                occ["aria-reference"]=occ.get("aria-reference",0)+1
                if r: findings.append(r)

    for n in nodes:
        if n.attrs.get("aria-hidden","").strip().lower()=="true" and any(_is_focusable(x) for x in [n,*list(_desc(n))]):
            r=_record(src,n,"aria-hidden-focusable","aria-hidden-focusable",occ.get("aria-hidden-focusable",0),
                      {"reason":"inclusive descendant is sequentially focusable"})
            occ["aria-hidden-focusable"]=occ.get("aria-hidden-focusable",0)+1
            if r: findings.append(r)

        if "aria-label" in n.attrs and not n.attrs["aria-label"].strip():
            interactive = n.tag in FOCUSABLE or n.attrs.get("role","").strip().lower() in {
                "button","link","checkbox","combobox","listbox","menuitem","radio","searchbox","slider","spinbutton","switch","tab","textbox"
            }
            if interactive:
                r=_record(src,n,"empty-aria-label","empty-aria-label",occ.get("empty-aria-label",0),
                          {"attribute":"aria-label","value":n.attrs["aria-label"]})
                occ["empty-aria-label"]=occ.get("empty-aria-label",0)+1
                if r: findings.append(r)

        if "tabindex" in n.attrs:
            try:
                value=int(n.attrs["tabindex"])
            except ValueError:
                value=None
            if value is not None and value>0:
                r=_record(src,n,"positive-tabindex","positive-tabindex",occ.get("positive-tabindex",0),
                          {"tabindex":value},advisory=True)
                occ["positive-tabindex"]=occ.get("positive-tabindex",0)+1
                if r: advisories.append(r)

    headings=[n for n in nodes if n.tag in {"h1","h2","h3","h4","h5","h6"} and n.hs=="visible"]
    previous=None
    for n in headings:
        level=int(n.tag[1])
        if previous is not None and level>previous+1:
            r=_record(src,n,"heading-order","advisory:heading-order",occ.get("heading-order",0),
                      {"previous_level":previous,"current_level":level},advisory=True)
            occ["heading-order"]=occ.get("heading-order",0)+1
            if r: advisories.append(r)
        previous=level

    return findings, advisories

def _desc(n):
    stack=list(reversed(n.children))
    while stack:
        x=stack.pop()
        yield x
        stack.extend(reversed(x.children))
