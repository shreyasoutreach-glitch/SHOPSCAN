"""shopscan.dom -- tolerant HTML tree builder.

Guarantees: never raises on hostile input; bounded depth and node count (limits are *recorded*, never silent);
visibility state is computed once per node (linear time); offsets/raw tag text are byte-exact against the source.
"""
import re
from html.parser import HTMLParser
from urllib.parse import urlsplit

MAX_DEPTH = 512
MAX_NODES = 300_000
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
AUTO_CLOSE = {"li": {"li"}, "option": {"option"}, "p": {"p"}, "dt": {"dt", "dd"}, "dd": {"dt", "dd"},
              "tr": {"tr", "td", "th"}, "td": {"td", "th"}, "th": {"td", "th"}}
NO_TEXT = {"script", "style", "template", "noscript"}
HARD_TAGS = {"template", "noscript", "head"}
UNCERTAIN_CLASS = {"hidden", "hide", "d-none", "is-hidden", "display-none", "invisible", "hidden-xs", "hidden-sm"}
STYLE_HIDE = re.compile(r"(?:^|;)\s*(?:display\s*:\s*none|visibility\s*:\s*hidden)", re.I)

class Node:
    __slots__ = ("tag", "attrs", "parent", "children", "text", "off", "raw", "depth", "hs")
    def __init__(self, tag, attrs=None, parent=None, off=0, raw=""):
        self.tag, self.attrs, self.parent, self.off, self.raw = tag, attrs or {}, parent, off, raw
        self.children, self.text = [], []
        self.depth = parent.depth + 1 if parent is not None else 0
        self.hs = "visible"

def own_hidden(n):
    at = n.attrs
    return (n.tag in HARD_TAGS or "hidden" in at or at.get("aria-hidden", "").strip().lower() == "true"
            or bool(STYLE_HIDE.search(at.get("style", ""))))

def _state(n, parent_state):
    if parent_state == "hard" or own_hidden(n):
        return "hard"
    at = n.attrs
    if (parent_state == "uncertain" or (n.tag == "details" and "open" not in at)
            or set(at.get("class", "").lower().split()) & UNCERTAIN_CLASS):
        return "uncertain"
    return "visible"

class Tree(HTMLParser):
    def __init__(self, src):
        super().__init__(convert_charrefs=True)
        self.root = Node("#root"); self.cur = self.root; self.src = src; self.count = 0; self.limitations = set()
        self.line_starts = [0] + [m.end() for m in re.finditer("\n", src)]
        try:
            self.feed(src); self.close()
        except Exception as e:
            self.limitations.add("parser_exception:" + type(e).__name__)
    def _off(self):
        line, col = self.getpos(); return self.line_starts[line - 1] + col
    def _foreign(self, tag):
        n = self.cur
        while n is not None:
            if n.tag in ("svg", "math"): return True
            n = n.parent
        return tag in ("svg", "math")
    def handle_starttag(self, tag, attrs):
        if self.count >= MAX_NODES:
            self.limitations.add("node_cap"); return
        closers = AUTO_CLOSE.get(tag)
        if closers:
            n = self.cur
            while n is not self.root and n.tag not in ("ul", "ol", "table", "select", "div", "body"):
                if n.tag in closers:
                    self.cur = n.parent; break
                n = n.parent
        a = {}
        for k, v in attrs:
            k = k.lower()
            if k not in a: a[k] = "" if v is None else v
        node = Node(tag, a, self.cur, self._off(), self.get_starttag_text() or "")
        node.hs = _state(node, self.cur.hs); self.cur.children.append(node); self.count += 1
        if tag not in VOID:
            if node.depth >= MAX_DEPTH: self.limitations.add("depth_cap")
            else: self.cur = node
    def handle_startendtag(self, tag, attrs):
        foreign = self._foreign(tag); self.handle_starttag(tag, attrs)
        if tag not in VOID and foreign and self.cur.tag == tag: self.handle_endtag(tag)
    def handle_endtag(self, tag):
        n = self.cur
        while n is not self.root:
            if n.tag == tag: self.cur = n.parent; return
            n = n.parent
    def handle_data(self, data): self.cur.text.append(data)
    def error(self, message): self.limitations.add("parser_error")

def walk(node):
    stack = list(reversed(node.children))
    while stack:
        n = stack.pop(); yield n; stack.extend(reversed(n.children))

def ws(s): return " ".join(s.split())

def element_path(n, max_segments=10):
    segs = []
    while n is not None and n.tag != "#root" and len(segs) < max_segments:
        idx = 1
        if n.parent is not None:
            for sib in n.parent.children:
                if sib is n: break
                if sib.tag == n.tag: idx += 1
        segs.append(f"{n.tag}:nth-of-type({idx})" if idx > 1 else n.tag); n = n.parent
    return ">".join(reversed(segs))

_DYN_ATTR = re.compile(r"^(id|style|nonce|data-.*|on.*|tabindex|for|aria-(describedby|controls|owns|labelledby)|key)$")
def _is_hashy(tok):
    for seg in re.split(r"[-_]", tok):
        if re.fullmatch(r"[0-9a-f]{8,}", seg) or re.search(r"\d{3,}", seg): return True
        if len(seg) >= 6 and re.search(r"\d", seg) and re.search(r"[a-z]", seg): return True
    return False

def _url_shape(v):
    try: path = urlsplit(v.strip()).path
    except ValueError: return ""
    seg = path.split("/"); return "/" + seg[1] if len(seg) > 1 else path

def stable_signature(rule, n):
    names = sorted(k for k in n.attrs if not _DYN_ATTR.match(k) and k not in ("class", "href", "src"))
    classes = sorted(c for c in n.attrs.get("class", "").lower().split() if not _is_hashy(c))[:6]
    shape = "|".join(f"{k}:{_url_shape(n.attrs[k])}" for k in ("href", "src") if k in n.attrs)
    return f"{rule}|{n.tag}|{','.join(names)}|{' '.join(classes)}|{shape}"
