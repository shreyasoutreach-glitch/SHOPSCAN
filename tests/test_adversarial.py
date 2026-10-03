import sys, random
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scan import analyze

SEED=1337

def cases():
    rng=random.Random(SEED)
    base=[
      '<!doctype html><html><head><title>Store</title></head><body><img src="p.jpg"><button></button><a href="/p"></a></body></html>',
      '<html><head><meta name="viewport" content="width=device-width,maximum-scale=1,user-scalable=no"></head><body><label><input type="text"></label></body></html>',
      '<html><head></head><body><div aria-hidden="true"><img src="x"></div><details><summary>Menu</summary><input></details></body></html>',
      '<html><head><title></title></head><body><iframe src="/x"></iframe><img role="presentation" src="d.svg"></body></html>',
      '<html><head><meta property="og:site_name" content="ACME"><title></title></head><body><button aria-label=""></button></body></html>',
    ]
    for i in range(40):
        s=rng.choice(base)
        if rng.random()<.55: s=s.replace("<body>","<body data-token='123456789'>")
        if rng.random()<.4: s=s.replace("<body>","<body><div class='hidden'>",1)
        if rng.random()<.25: s=s.replace("</body>","</div></body>")
        yield i,s

def test_adversarial_corpus_never_crashes():
    for _,src in cases():
        result=analyze(src,"https://sim.example/")
        assert "findings" in result and "advisories" in result
        assert result["node_count"] < 300000
