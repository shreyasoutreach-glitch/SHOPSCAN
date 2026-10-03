import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from repair import repair_html, SAFE, UNREPAIRABLE

def f(rule, src, needle=None):
    needle = needle or src
    off = src.index(needle)
    return {"base_rule":rule,"rule":rule,"off":off,"length":len(needle),"snippet":needle,"signature":rule,"occurrence":0}

def test_viewport_repair():
    src='<meta name="viewport" content="width=device-width, maximum-scale=1, user-scalable=no">'
    r=repair_html(src,[f("meta-viewport",src)])
    assert 'user-scalable=yes' in r["html"] and r["repairs"][0]["confidence"]==SAFE

def test_decorative_image_repair():
    src='<img src="hero.svg" role="presentation">'
    r=repair_html(src,[f("image-alt",src)])
    assert 'alt=""' in r["html"] and not r["proposals"]

def test_meaningful_image_not_guessed():
    src='<img src="product.jpg">'
    r=repair_html(src,[f("image-alt",src)])
    assert r["html"]==src and r["proposals"][0]["confidence"]==UNREPAIRABLE

def test_language_requires_explicit_input():
    src='<html><head></head><body></body></html>'
    r=repair_html(src,[f("html-has-lang",src,"<html>")])
    assert r["html"]==src

def test_language_can_be_repaired_when_configured():
    src='<html><head></head><body></body></html>'
    r=repair_html(src,[f("html-has-lang",src,"<html>")],default_language="en")
    assert '<html lang="en">' in r["html"]

def test_empty_title_can_use_site_name():
    src='<html><head><meta property="og:site_name" content="ACME"><title></title></head></html>'
    r=repair_html(src,[f("document-title",src,"<title></title>")])
    assert '<title>ACME</title>' in r["html"]

def test_semantic_names_are_never_invented():
    src='<button></button><a href="/x"></a><input type="text"><iframe src="/frame"></iframe>'
    fs=[f("button-name",src,"<button></button>"),f("link-name",src,'<a href="/x"></a>'),
        f("label",src,'<input type="text">'),f("frame-title",src,'<iframe src="/frame"></iframe>')]
    r=repair_html(src,fs)
    assert r["html"]==src and len(r["proposals"])==4
