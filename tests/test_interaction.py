from interaction import _risk_word, _safe_toggle

def test_transactional_controls_are_never_safe_to_probe():
    assert _risk_word("Add to cart")
    assert not _safe_toggle("Add to cart")
    assert _risk_word("Checkout")

def test_disclosure_controls_are_safe_probe_candidates():
    assert _safe_toggle("Open menu")
    assert _safe_toggle("Show filters")
    assert _safe_toggle("Search")

def test_neutral_button_is_not_automatically_clicked():
    assert not _safe_toggle("Learn more")
