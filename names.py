"""shopscan.names -- accessible-name evidence (static-HTML subset of W3C accname."""
from dom import NO_TEXT, own_hidden
TRAVERSAL_BUDGET = 2000

def build_id_index(nodes):
    idx = {}
    for n in nodes:
        i = n.attrs.get("id")
        if i and i not in idx: idx[i] = n
    return idx

def get_element_by_id(index, id_): return index.get(id_) if id_ else None

def parse_idrefs(value):
    seen, out = set(), []
    for t in (value or "").split():
        if t not in seen: seen.add(t); out.append(t)
    return out

def _walk_content(root, budget):
    stack = list(reversed(root.children))
    while stack:
        n = stack.pop(); budget[0] -= 1
        if budget[0] < 0: return
        if n.tag in NO_TEXT or own_hidden(n): continue
        yield n; stack.extend(reversed(n.children))

def extract_accessible_text(node, budget=None):
    budget = budget or [TRAVERSAL_BUDGET]
    parts = [t for t in node.text] if node.tag not in NO_TEXT else []
    for n in _walk_content(node, budget):
        al = n.attrs.get("aria-label", "").strip()
        if al: parts.append(al); continue
        if n.tag == "img" and n.attrs.get("alt", "").strip(): parts.append(n.attrs["alt"])
        if n.tag == "title" and n.parent is not None and n.parent.tag == "svg": parts.extend(n.text)
        parts.extend(n.text)
    return " ".join(" ".join(parts).split()), budget[0] < 0

def resolve_aria_labelledby(node, index, budget=None):
    refs = parse_idrefs(node.attrs.get("aria-labelledby", ""))
    missing, empty, texts, exhausted = [], [], [], False
    budget = budget or [TRAVERSAL_BUDGET]
    for r in refs:
        el = get_element_by_id(index, r)
        if el is None: missing.append(r); continue
        al = el.attrs.get("aria-label", "").strip()
        t, ex = (al, False) if al else extract_accessible_text(el, budget)
        exhausted = exhausted or ex
        if t: texts.append(t)
        else: empty.append(r)
    text = " ".join(texts).strip()
    return {"refs": refs, "missing": missing, "empty": empty, "text": text, "valid": bool(text), "exhausted": exhausted}

def resolve_aria_describedby(node, index):
    r = resolve_aria_labelledby(type(node)("x", {"aria-labelledby": node.attrs.get("aria-describedby", "")}), index)
    return {"refs": r["refs"], "missing": r["missing"], "text": r["text"]}

def _descendant_title(node, budget):
    for n in _walk_content(node, budget):
        if n.attrs.get("title", "").strip(): return True
    return False

def name_evidence(node, index, labels, kind):
    at = node.attrs; strong, weak, invalid = [], [], []; budget = [TRAVERSAL_BUDGET]
    if at.get("role", "").strip().lower() in ("presentation", "none"):
        return {"strength": "strong", "strong": ["role-presentation"], "weak": [], "invalid": []}
    if "aria-labelledby" in at:
        r = resolve_aria_labelledby(node, index, budget)
        if r["valid"]: strong.append("aria-labelledby")
        else: invalid.append("aria-labelledby:" + ("missing" if r["missing"] and not r["empty"] else "empty-or-missing"))
    if "aria-label" in at:
        (strong if at["aria-label"].strip() else invalid).append("aria-label" if at["aria-label"].strip() else "aria-label:empty")
    if kind == "image":
        if at.get("alt") is not None:
            return {"strength": "strong" if at.get("alt", "").strip() else "strong",
                    "strong": ["alt"] if at.get("alt", "").strip() else ["empty-alt"],
                    "weak": [], "invalid": []}
    if kind == "control":
        exhausted = False
        cand = list(labels.get(at.get("id", ""), [])) if at.get("id") else []
        a = node.parent
        while a is not None:
            if a.tag == "label": cand.append(a); break
            a = a.parent
        for lab in cand:
            t, ex = extract_accessible_text(lab, [TRAVERSAL_BUDGET]); exhausted = exhausted or ex
            if t: strong.append("label")
            else: invalid.append("label:empty")
            if exhausted: break
        if exhausted: return {"strength": "unknown", "strong": strong, "weak": weak, "invalid": invalid}
        if at.get("title", "").strip(): weak.append("title")
        if node.tag in ("input", "textarea") and at.get("placeholder", "").strip(): weak.append("placeholder")
    else:
        if kind == "frame":
            if at.get("title", "").strip(): strong.append("title")
        else:
            text, ex = extract_accessible_text(node, budget)
            if text: strong.append("content")
            elif ex: return {"strength": "unknown", "strong": strong, "weak": weak, "invalid": invalid}
            if at.get("title", "").strip() or _descendant_title(node, budget): weak.append("title")
    strength = "strong" if strong else ("weak" if weak else "none")
    return {"strength": strength, "strong": strong, "weak": weak, "invalid": invalid}
