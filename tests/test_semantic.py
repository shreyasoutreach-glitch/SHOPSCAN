import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from semantic import SAFE_AUTO_REPAIR, REVIEW, UNREPAIRABLE, infer
from repair import repair_html


def finding(rule, src, needle=None):
    needle = needle or src
    return {
        "base_rule": rule, "rule": rule, "off": src.index(needle),
        "length": len(needle), "snippet": needle, "signature": rule, "occurrence": 0,
    }


def test_button_action_token_is_safe():
    src = '<button data-action="add-to-cart"></button>'
    p = infer(src, finding("button-name", src))
    assert p["confidence"] == SAFE_AUTO_REPAIR
    assert p["value"] == "Add to cart"


def test_link_route_is_safe():
    src = '<a href="/cart"></a>'
    p = infer(src, finding("link-name", src))
    assert p["confidence"] == SAFE_AUTO_REPAIR
    assert p["value"] == "Cart"


def test_field_autocomplete_is_safe():
    src = '<input autocomplete="email">'
    p = infer(src, finding("label", src))
    assert p["confidence"] == SAFE_AUTO_REPAIR
    assert p["value"] == "Email"


def test_known_iframe_provider_is_safe():
    src = '<iframe src="https://www.youtube.com/embed/abc"></iframe>'
    p = infer(src, finding("frame-title", src))
    assert p["confidence"] == SAFE_AUTO_REPAIR
    assert p["value"] == "YouTube video"


def test_figure_caption_is_safe_image_alt():
    src = '<figure><img src="shoe.jpg"><figcaption>Black running shoe</figcaption></figure>'
    p = infer(src, finding("image-alt", src, '<img src="shoe.jpg">'))
    assert p["confidence"] == SAFE_AUTO_REPAIR
    assert p["value"] == "Black running shoe"


def test_filename_is_never_used_as_alt():
    src = '<img src="/products/black-shoe-final-v4.jpg">'
    p = infer(src, finding("image-alt", src))
    assert p["confidence"] == UNREPAIRABLE


def test_unknown_button_is_never_guessed():
    src = '<button data-testid="abc123"></button>'
    p = infer(src, finding("button-name", src))
    assert p["confidence"] == UNREPAIRABLE


def test_site_name_is_review_not_auto_title():
    src = '<html><head><meta property="og:site_name" content="ACME"><title></title></head></html>'
    p = infer(src, finding("document-title", src, '<title></title>'))
    assert p["confidence"] == REVIEW


def test_explicit_locale_is_safe_language():
    src = '<html><head><meta property="og:locale" content="en_US"></head></html>'
    p = infer(src, finding("html-has-lang", src, '<html>'))
    assert p["confidence"] == SAFE_AUTO_REPAIR
    assert p["value"] == "en-US"


def test_repair_applies_semantic_button_fix():
    src = '<button data-action="close"></button>'
    r = repair_html(src, [finding("button-name", src)])
    assert '<button data-action="close" aria-label="Close"></button>' in r["html"]
    assert len(r["repairs"]) == 1


def test_decorative_image_is_safe():
    src = '<img role="presentation" src="icon.svg">'
    r = repair_html(src, [finding("image-alt", src)])
    assert 'alt=""' in r["html"]
    assert not r["proposals"]
