import sys,types
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from rendered import CONFIRMED,ERROR,NOT_REPRODUCED
from rendered_playwright import PlaywrightVerifier

def fake_playwright(found=True):
    class Response: status=200
    class Page:
        url="https://example.com/"
        def on(self,*args): pass
        def goto(self,*args,**kwargs): return Response()
        def wait_for_timeout(self,*args): pass
        def evaluate(self,js,candidates=None):
            if candidates is None:return None
            return {"candidates":[dict(c,count=1 if found else 0,found=found) for c in candidates],
                    "element_count":42,"title":"Example","ready_state":"complete","scroll_height":2000}
        def close(self): pass
    class Context:
        def new_page(self,**kwargs): return Page()
        def close(self): pass
    class Browser:
        def new_context(self,**kwargs): return Context()
        def close(self): pass
    class PW:
        chromium=types.SimpleNamespace(launch=lambda **kwargs:Browser())
        def __enter__(self): return self
        def __exit__(self,*args): pass
    return PW()

def test_confirmed_across_viewports(monkeypatch):
    module=types.SimpleNamespace(sync_playwright=lambda:fake_playwright(True))
    monkeypatch.setitem(sys.modules,"playwright.sync_api",module)
    monkeypatch.setitem(sys.modules,"playwright",types.SimpleNamespace())
    f={"signature":"button-name|button|||","occurrence":0}; v=PlaywrightVerifier(settle_ms=0)
    assert v.verify("https://example.com",[f])[(f["signature"],0)]==CONFIRMED
    assert len(v.last_evidence["viewports"])==2

def test_not_reproduced(monkeypatch):
    module=types.SimpleNamespace(sync_playwright=lambda:fake_playwright(False))
    monkeypatch.setitem(sys.modules,"playwright.sync_api",module)
    monkeypatch.setitem(sys.modules,"playwright",types.SimpleNamespace())
    f={"signature":"button-name|button|||","occurrence":0}; v=PlaywrightVerifier(settle_ms=0)
    assert v.verify("https://example.com",[f])[(f["signature"],0)]==NOT_REPRODUCED

def test_browser_import_failure(monkeypatch):
    monkeypatch.delitem(sys.modules,"playwright.sync_api",raising=False)
    monkeypatch.setitem(sys.modules,"playwright",types.SimpleNamespace())
    f={"signature":"button-name|button|||","occurrence":0}; v=PlaywrightVerifier()
    assert v.verify("https://example.com",[f])[(f["signature"],0)]==ERROR
