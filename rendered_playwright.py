"""High-confidence browser verification for ShopScan.

The static scanner finds candidates from source HTML. This module verifies those candidates
against the hydrated browser DOM at multiple responsive viewports, records evidence, and
fails conservatively when the browser cannot produce a trustworthy observation.
"""
from rendered import RenderedVerifier, CONFIRMED, NOT_REPRODUCED, ERROR
from fetch import is_public_url
from urllib.parse import urlsplit

OBSERVE_JS = r'''
(candidates) => {
  const DYN=/^(id|style|nonce|data-.*|on.*|tabindex|for|aria-(describedby|controls|owns|labelledby)|key)$/i;
  const hashy=s=>s.split(/[-_]/).some(x=>/^[0-9a-f]{8,}$/i.test(x)||/\d{3,}/.test(x)||(x.length>=6&&/\d/.test(x)&&/[a-z]/i.test(x)));
  const shape=e=>{
    const names=[...e.attributes].map(a=>a.name.toLowerCase()).filter(k=>!DYN.test(k)&&k!=='class'&&k!=='href'&&k!=='src').sort();
    const cls=[...e.classList].map(x=>x.toLowerCase()).filter(x=>!hashy(x)).sort().slice(0,6).join(' ');
    const path=v=>{try{return '/'+((new URL(v,location.href)).pathname.split('/')[1]||'')}catch(_){return ''}};
    const links=[]; if(e.hasAttribute('href'))links.push('href:'+path(e.getAttribute('href'))); if(e.hasAttribute('src'))links.push('src:'+path(e.getAttribute('src')));
    return names.join(',')+'|'+cls+'|'+links.join('|');
  };
  const visible=e=>{
    if(e.closest('[hidden],template,noscript,[aria-hidden="true"]'))return false;
    const s=getComputedStyle(e); return s.display!=='none'&&s.visibility!=='hidden'&&parseFloat(s.opacity||'1')>0;
  };
  const text=e=>(e.textContent||'').replace(/\s+/g,' ').trim();
  const named=e=>{
    const a=e.getAttribute('aria-label'); if(a&&a.trim())return {ok:true,source:'aria-label'};
    const r=e.getAttribute('aria-labelledby');
    if(r){const v=r.split(/\s+/).map(id=>document.getElementById(id)).filter(Boolean).map(text).filter(Boolean).join(' '); if(v)return {ok:true,source:'aria-labelledby'};}
    if(e.tagName==='IMG'&&e.hasAttribute('alt'))return {ok:true,source:'alt'};
    if(e.tagName==='IFRAME'||e.tagName==='FRAME')return e.getAttribute('title')?.trim()?{ok:true,source:'title'}:{ok:false,source:'none'};
    if(e.id&&[...document.querySelectorAll('label')].some(x=>x.htmlFor===e.id&&text(x)))return {ok:true,source:'label-for'};
    if(e.closest('label')&&text(e.closest('label')))return {ok:true,source:'label'};
    if(text(e))return {ok:true,source:'text'};
    if(e.getAttribute('title')?.trim())return {ok:true,source:'title'};
    if(e.getAttribute('value')?.trim())return {ok:true,source:'value'};
    return {ok:false,source:'none'};
  };
  const deep=[];
  const visit=root=>{for(const e of root.children||[]){deep.push(e);if(e.shadowRoot)visit(e.shadowRoot);visit(e);}};
  visit(document);
  const byRule={};
  const add=(rule,e)=>{const s=rule+'|'+e.tagName.toLowerCase()+'|'+shape(e);(byRule[s]??=[]).push(e)};
  for(const e of deep){
    if(!visible(e))continue; const t=e.tagName.toLowerCase();
    if(t==='img'&&!e.hasAttribute('alt')&&e.getAttribute('role')!=='presentation'&&e.getAttribute('role')!=='none'&&!named(e).ok)add('image-alt',e);
    if(['input','textarea','select'].includes(t)){
      const typ=(e.getAttribute('type')||'text').toLowerCase();
      if(!(t==='input'&&['hidden','submit','reset','button','image'].includes(typ))&&!named(e).ok)add('label',e);
    }
    if(t==='button'&&!named(e).ok)add('button-name',e);
    if(t==='a'&&e.hasAttribute('href')&&!named(e).ok)add('link-name',e);
    if((t==='iframe'||t==='frame')&&!named(e).ok)add('frame-title',e);
    if(t==='html'&&!((e.getAttribute('lang')||e.getAttribute('xml:lang')||'').trim()))add('html-has-lang',e);
    if(t==='meta'&&(e.getAttribute('name')||'').toLowerCase()==='viewport'){
      const c=(e.getAttribute('content')||'').toLowerCase();
      const off=/user-scalable\s*=\s*(no|0)\b/.test(c);
      const m=c.match(/maximum-scale\s*=\s*([0-9.]+)/); let capped=false; try{capped=!!m&&Number(m[1])<=1}catch(_){}
      if(off||capped)add('meta-viewport',e);
    }
  }
  const html=deep.find(e=>e.tagName.toLowerCase()==='html');
  if(html){
    const title=[...deep].find(e=>e.tagName.toLowerCase()==='title'&&e.parentElement&&(e.parentElement.tagName.toLowerCase()==='head'||e.parentElement.tagName.toLowerCase()==='html'));
    if(!title||!text(title))add('document-title',html);
  }
  const focusable=e=>{
    if(e.disabled||e.getAttribute("aria-disabled")==="true")return false;
    const ti=e.getAttribute("tabindex");
    if(ti!==null){const n=Number(ti);return Number.isFinite(n)&&n>=0}
    const t=e.tagName.toLowerCase();
    return ["button","input","select","textarea","summary","iframe"].includes(t)||(t==="a"&&e.hasAttribute("href"));
  };
  const ids={};
  for(const e of deep){const id=e.getAttribute("id");if(id) (ids[id]??=[]).push(e);}
  for(const e of deep){
    if(e.hasAttribute("id")&&ids[e.getAttribute("id")]?.length>1)add("duplicate-id",e);
    for(const attr of ["aria-labelledby","aria-describedby","aria-owns","aria-activedescendant"]){
      const raw=(e.getAttribute(attr)||"").trim(); if(!raw)continue;
      const missing=raw.split(/\s+/).some(id=>!document.getElementById(id));
      if(missing)add("aria-reference",e);
    }
    if(e.getAttribute("aria-label")!==null&&!e.getAttribute("aria-label").trim()&&
       (focusable(e)||["button","link","checkbox","combobox","listbox","menuitem","radio","searchbox","slider","spinbutton","switch","tab","textbox"].includes((e.getAttribute("role")||"").toLowerCase()))) add("empty-aria-label",e);
    if(e.getAttribute("aria-hidden")==="true"&&[...e.querySelectorAll("a[href],button,input,select,textarea,summary,iframe,[tabindex]")].some(focusable)) add("aria-hidden-focusable",e);
  }
  const counts={}; for(const [s,els] of Object.entries(byRule))counts[s]=els.length;
  const dynamic_findings=[];
  const dynamicRules=["image-alt","label","button-name","link-name","frame-title","html-has-lang","document-title","meta-viewport","duplicate-id","aria-reference","empty-aria-label","aria-hidden-focusable"];
  for(const [s,els] of Object.entries(byRule)){
    const [rule,tag,shapeValue]=s.split("|",2);
    if(!dynamicRules.includes(rule)) continue;
    els.forEach((e,occurrence)=>dynamic_findings.push({
      rule,tag,shape:shapeValue,occurrence,
      signature:"dynamic|"+rule+"|"+tag+"|"+shapeValue,
      evidence:{tag,shape:shapeValue,outer:e.outerHTML?.slice(0,500)||""}
    }));
  }
  const scriptUrls=[...document.scripts].map(x=>x.src).filter(Boolean);
  const iframeUrls=[...document.querySelectorAll("iframe,frame")].map(x=>x.src).filter(Boolean);
  const markerHints=[...document.querySelectorAll("[id],[class]")].slice(0,2500).map(e=>(e.id||"")+" "+(typeof e.className==="string"?e.className:"")).filter(Boolean);
  const globalHints=["acsbapp","accessiBe","UserWay","userway","AudioEye","EqualWeb","equalweb","LevelAccess","AccessiWay"].filter(k=>k in window);
  return {
    candidates:candidates.map(c=>({signature:c.signature,occurrence:Number(c.occurrence||0),count:counts[c.signature]||0,found:(counts[c.signature]||0)>Number(c.occurrence||0)})),
    dynamic_findings,script_urls:scriptUrls,iframe_urls:iframeUrls,marker_hints:markerHints.slice(0,200),
    global_hints:globalHints,
    element_count:deep.length,title:document.title,final_url:location.href,ready_state:document.readyState,scroll_height:document.documentElement?.scrollHeight||0
  };
}
''';

DEFAULT_VIEWPORTS = ((1440, 1000), (390, 844))


class PlaywrightVerifier(RenderedVerifier):
    name = "playwright-dom-v2"

    def __init__(self, timeout_ms=20000, settle_ms=1200, headless=True, viewports=None):
        self.timeout_ms=max(1000,int(timeout_ms)); self.settle_ms=max(0,int(settle_ms)); self.headless=headless
        self.viewports=tuple(viewports or DEFAULT_VIEWPORTS); self.last_evidence={}

    def _guard(self, initial_url):
        initial_host=(urlsplit(initial_url).hostname or "").lower().rstrip(".")
        cache={}
        def guard(route):
            target=route.request.url
            if target.startswith(("data:","blob:","about:")):
                route.continue_(); return
            try:
                host=(urlsplit(target).hostname or "").lower().rstrip(".")
                if host and host==initial_host:
                    route.continue_(); return
                if host and host not in cache:
                    cache[host]=is_public_url(target)
                if cache.get(host,False): route.continue_()
                else: route.abort()
            except Exception:
                route.abort()
        return guard

    def verify(self, url, findings):
        self.last_dynamic_findings=[]
        candidates=[{"signature":f["signature"],"occurrence":f.get("occurrence",0)} for f in findings]
        evidence={"status":"OK","url":url,"viewports":[],"browser":"chromium","candidate_count":len(candidates)}
        aggregate={}; successful=0; errors=[]
        try:
            from playwright.sync_api import sync_playwright
        except Exception as exc:
            self.last_evidence={"status":"ERROR","error":type(exc).__name__+": "+str(exc),"candidate_count":len(candidates)}
            return {(f["signature"],f.get("occurrence",0)):ERROR for f in findings}
        try:
            with sync_playwright() as p:
                browser=p.chromium.launch(headless=self.headless,args=["--disable-dev-shm-usage"])
                context=browser.new_context(ignore_https_errors=True,service_workers="block",locale="en-US",timezone_id="America/New_York")
                for width,height in self.viewports:
                    page=context.new_page(); page.set_viewport_size({"width":width,"height":height})
                    console_errors=[]; page_errors=[]; request_failures=[]
                    page.on("console",lambda msg: console_errors.append(msg.type) if msg.type=="error" else None)
                    page.on("pageerror",lambda exc: page_errors.append(str(exc)[:300]))
                    page.on("requestfailed",lambda req: request_failures.append(req.url[:300]))
                    page.route("**/*",self._guard(url))
                    try:
                        response=page.goto(url,wait_until="domcontentloaded",timeout=self.timeout_ms)
                        page.wait_for_timeout(self.settle_ms)
                        page.evaluate("window.scrollTo(0, document.body ? document.body.scrollHeight : 0)")
                        page.wait_for_timeout(min(800,self.settle_ms))
                        page.evaluate("window.scrollTo(0, 0)")
                        observed=page.evaluate(OBSERVE_JS,candidates)
                        successful += 1
                        for item in observed.get("candidates",[]):
                            key=(item["signature"],item["occurrence"])
                            aggregate[key]=aggregate.get(key,False) or bool(item["found"])
                        evidence["viewports"].append({"width":width,"height":height,"http_status":response.status if response else None,"final_url":page.url,"title":observed.get("title",""),"ready_state":observed.get("ready_state"),"element_count":observed.get("element_count",0),"scroll_height":observed.get("scroll_height",0),"console_error_count":len(console_errors),"page_error_count":len(page_errors),"request_failure_count":len(request_failures),"page_errors":page_errors[:3],
                            "script_urls":observed.get("script_urls",[]),"iframe_urls":observed.get("iframe_urls",[]),
                            "marker_hints":observed.get("marker_hints",[]),"global_hints":observed.get("global_hints",[]),"dynamic_findings":observed.get("dynamic_findings",[])})
                    except Exception as exc:
                        errors.append({"viewport":[width,height],"error":type(exc).__name__+": "+str(exc)[:300]})
                        evidence["viewports"].append({"width":width,"height":height,"error":errors[-1]["error"]})
                    finally:
                        page.close()
                context.close(); browser.close()
            if successful==0:
                evidence["status"]="ERROR"; evidence["errors"]=errors
            elif errors:
                evidence["status"]="PARTIAL"; evidence["errors"]=errors
            evidence["successful_viewports"]=successful; evidence["failed_viewports"]=len(errors)
            # Expose independent hydrated-DOM findings. These are not restricted to
            # the static candidate set, which lets the browser discover injected widget defects.
            dynamic_seen={}
            for vp in evidence.get("viewports",[]):
                for item in vp.get("dynamic_findings",[]):
                    key=(item.get("rule"),item.get("tag"),item.get("shape"),int(item.get("occurrence",0)))
                    dynamic_seen[key]=item
            self.last_dynamic_findings=[]
            for (rule,tag,shape,occurrence),item in dynamic_seen.items():
                self.last_dynamic_findings.append({
                    "rule":rule,"base_rule":rule,"impact":{"image-alt":"critical","label":"critical","button-name":"critical","link-name":"serious","frame-title":"serious","html-has-lang":"serious","document-title":"serious","meta-viewport":"moderate","duplicate-id":"serious","aria-reference":"serious","empty-aria-label":"serious","aria-hidden-focusable":"serious"}.get(rule,"moderate"),
                    "observation":"hydrated_browser_dom","signature":item.get("signature"),
                    "occurrence":occurrence,"url":url,"viewport_evidence":[v for v in evidence.get("viewports",[]) if any(d.get("signature")==item.get("signature") for d in v.get("dynamic_findings",[]))],
                    "evidence":item.get("evidence",{})
                })
            self.last_evidence=evidence
            return {(f["signature"],f.get("occurrence",0)):(CONFIRMED if aggregate.get((f["signature"],f.get("occurrence",0)),False) else (NOT_REPRODUCED if successful else ERROR)) for f in findings}
        except Exception as exc:
            evidence["status"]="ERROR"; evidence["errors"]=errors+[{"error":type(exc).__name__+": "+str(exc)[:300]}]; self.last_evidence=evidence
            return {(f["signature"],f.get("occurrence",0)):ERROR for f in findings}
