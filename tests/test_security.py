import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fetch import is_public_url
from scan import analyze


def test_private_literal_destinations_are_blocked():
    assert not is_public_url("http://127.0.0.1/")
    assert not is_public_url("http://10.0.0.1/")
    assert not is_public_url("http://169.254.169.254/latest/meta-data/")
    assert not is_public_url("http://[::1]/")


def test_non_http_destination_is_blocked():
    assert not is_public_url("file:///etc/passwd")
    assert not is_public_url("gopher://127.0.0.1:6379/")


def test_empty_title_uses_html_node_signature():
    src = "<html><head><title></title></head><body></body></html>"
    result = analyze(src, "https://example.invalid/")
    finding = next(x for x in result["findings"] if x["base_rule"] == "document-title")
    assert finding["off"] == 0
    assert finding["snippet"] == "<html>"
