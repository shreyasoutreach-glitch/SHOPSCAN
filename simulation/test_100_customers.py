import json,secrets
from pathlib import Path
from scan import analyze
from rendered_playwright import OBSERVE_JS
from playwright.sync_api import sync_playwright

ROOT=Path(__file__).resolve().parents[1]
rng=secrets.SystemRandom()
rules=["image_alt","label","button_name","link_name","frame_title","html_lang","document_title","meta_viewport","duplicate_id","aria_reference","empty_aria_label","aria_hidden_focusable"]
cats=["fashion","beauty","electronics","jewelry","home","food","health","sports","travel","pets","automotive","books"]
platforms=["shopify","woocommerce","custom","magento","bigcommerce"]
customers=[]
for i in range(1,101):
    variables={r:rng.random()<rng.uniform(.08,.38) for r in rules}
    customers.append({"id":f"SIM-{i:03d}","name":f"SimMerchant-{secrets.token_hex(3)}","category":rng.choice(cats),
      "platform":rng.choice(platforms),"traffic_band":rng.choice(["low","mid","high","very_high"]),
      "theme_complexity":rng.randint(1,10),"js_density":rng.randint(1,10),"locale":rng.choice(["en","en-IN","fr","de","es","ar"]),
      "mobile_weight":round(rng.uniform(.31,.91),3),"discount_logic":rng.choice(["none","coupon","tiered","flash","member"]),
      "overlay_present":rng.random()<.42,"variables":variables})
(ROOT/"customers_100.json").write_text(json.dumps(customers,indent=2))

def page(c):
 v=c["variables"]; title="" if v["document_title"] else f"<title>{c['name']}</title>"
 vp='<meta name="viewport" content="width=device-width, maximum-scale=1, user-scalable=no">' if v["meta_viewport"] else '<meta name="viewport" content="width=device-width, initial-scale=1">'
 lang="" if v["html_lang"] else ' lang="en-IN"'
 x=f"<!doctype html><html{lang}><head>{title}{vp}</head><body><h1>{c['category'].title()}</h1>"
 x+= '<img src="/hero.jpg">' if v["image_alt"] else '<img src="/hero.jpg" alt="Hero product">'
 x+= '<input type="email" name="email">' if v["label"] else '<label for="email">Email</label><input id="email" type="email">'
 x+= '<button aria-label=""> </button>' if v["button_name"] else '<button>Add to cart</button>'
 x+= '<a href="/sale"><span></span></a>' if v["link_name"] else '<a href="/sale">Sale</a>'
 x+= '<iframe src="https://example.com/embed"></iframe>' if v["frame_title"] else '<iframe title="Product video" src="https://example.com/embed"></iframe>'
 x+= '<div id="dup">A</div><div id="dup">B</div>' if v["duplicate_id"] else '<div id="unique">A</div><div id="unique2">B</div>'
 x+= '<button aria-labelledby="missing-id">Buy</button>' if v["aria_reference"] else '<button aria-label="Buy">Buy</button>'
 x+= '<button aria-label="">Checkout</button>' if v["empty_aria_label"] else '<button aria-label="Checkout">Checkout</button>'
 x+= '<div aria-hidden="true"><button>Hidden action</button></div>' if v["aria_hidden_focusable"] else '<div aria-hidden="true"><span>Decorative</span></div>'
 return x+"</body></html>"

m={"image_alt":"image-alt","label":"label","button_name":"button-name","link_name":"link-name","frame_title":"frame-title",
"html_lang":"html-has-lang","document_title":"document-title","meta_viewport":"meta-viewport","duplicate_id":"duplicate-id",
"aria_reference":"aria-reference","empty_aria_label":"empty-aria-label","aria_hidden_focusable":"aria-hidden-focusable"}
static=set(["image-alt","label","button-name","link-name","frame-title","html-has-lang","document-title","meta-viewport"])
static_exp=static_hit=browser_exp=browser_hit=0; rows=[]
for c in customers:
 out=analyze(page(c),"https://sim.invalid/"+c["id"])
 found={f.get("base_rule") or f.get("rule") for f in out["findings"]}
 expected={m[k] for k,v in c["variables"].items() if v}
 e=expected&static; h=e&found; static_exp+=len(e); static_hit+=len(h)
 rows.append({"id":c["id"],"expected":sorted(e),"detected":sorted(h),"missed":sorted(e-h),"findings":len(out["findings"])})

with sync_playwright() as p:
 b=p.chromium.launch(headless=True); pg=b.new_page(viewport={"width":390,"height":844})
 for c in customers:
  expected={m[k] for k,v in c["variables"].items() if v}; browser_exp+=len(expected)
  pg.set_content(page(c),wait_until="domcontentloaded")
  got={x.get("rule") for x in pg.evaluate(OBSERVE_JS,[])["dynamic_findings"]}
  browser_hit+=len(expected&got)
 b.close()
report={"customers":100,"static_expected":static_exp,"static_detected":static_hit,"static_recall":static_hit/static_exp,
"browser_expected":browser_exp,"browser_detected":browser_hit,"browser_recall":browser_hit/browser_exp,
"missed_static":[x for x in rows if x["missed"]],"random_seed":"system-random/non-reproducible","generated_customers":customers}
(ROOT/"results.json").write_text(json.dumps(report,indent=2))
print(json.dumps({k:report[k] for k in ["customers","static_expected","static_detected","static_recall","browser_expected","browser_detected","browser_recall"]},indent=2))
if report["static_recall"]<.95 or report["browser_recall"]<.90: raise SystemExit("ADVERSARIAL SIMULATION FAILED")

# Final gate rerun after dependency pin.
