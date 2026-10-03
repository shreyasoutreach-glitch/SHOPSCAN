import json, random, os
from pathlib import Path
from scan import analyze
from repair import repair_html

SEED=1337
OUT=Path(os.getenv("A11YFORGE_LAB_OUT","out/a11yforge_simulations.jsonl"))

def cases():
    rng=random.Random(SEED)
    base=[
      ("missing-image-alt",'<html lang="en"><head><title>Store</title></head><body><img src="p.jpg"></body></html>'),
      ("empty-button",'<html lang="en"><head><title>Store</title></head><body><button></button></body></html>'),
      ("empty-link",'<html lang="en"><head><title>Store</title></head><body><a href="/p"></a></body></html>'),
      ("viewport-lock",'<html lang="en"><head><title>Store</title><meta name="viewport" content="width=device-width,maximum-scale=1,user-scalable=no"></head><body></body></html>'),
      ("decorative-image",'<html lang="en"><head><title>Store</title></head><body><img role="presentation" src="icon.svg"></body></html>'),
      ("missing-language",'<html><head><title>Store</title></head><body></body></html>'),
      ("empty-title-with-site-name",'<html lang="en"><head><meta property="og:site_name" content="ACME"><title></title></head><body></body></html>'),
      ("missing-iframe-title",'<html lang="en"><head><title>Store</title></head><body><iframe src="/checkout"></iframe></body></html>'),
    ]
    for i in range(64):
        name,src=rng.choice(base)
        if i % 3 == 0: src=src.replace("<body>","<body data-react-props='123456789'>",1)
        if i % 5 == 0: src=src.replace("<body>","<body><div class='hidden'>",1).replace("</body>","</div></body>",1)
        yield i,name,src

def main():
    OUT.parent.mkdir(parents=True,exist_ok=True)
    rows=[]; counts={"cases":0,"crashed":0,"changed":0,"proposals":0}
    for i,name,src in cases():
        counts["cases"]+=1
        try:
            result=analyze(src,"https://simulation.invalid/")
            repaired=repair_html(src,result["findings"])
            row={"id":i,"case":name,"findings":[x["base_rule"] for x in result["findings"]],
                 "advisories":[x["rule"] for x in result["advisories"]],
                 "repairs":repaired["repairs"],"proposals":repaired["proposals"],
                 "changed":repaired["changed"],"complete":result["complete"],"node_count":result["node_count"]}
            counts["changed"]+=int(row["changed"]); counts["proposals"]+=len(row["proposals"])
        except Exception as exc:
            counts["crashed"]+=1
            row={"id":i,"case":name,"error":type(exc).__name__+": "+str(exc)}
        rows.append(row)
    with OUT.open("w") as f:
        for row in rows: f.write(json.dumps(row,separators=(",",":"))+"\n")
    print(json.dumps(counts,sort_keys=True))

if __name__=="__main__":
    main()
