"""A11yForge browser interaction audit.

This is a read-only, side-effect-minimizing interaction layer. It never submits forms,
adds products, changes account state, or follows destructive controls. It exercises keyboard
focus and only probes controls that are strongly classified as disclosure/navigation toggles.
"""
from urllib.parse import urlsplit
from fetch import is_public_url

INTERACTION_VERSION = "1.0.0"

SAFE_TOGGLE_WORDS = {
    "menu", "navigation", "nav", "filter", "filters", "sort", "sorting",
    "accordion", "details", "show", "hide", "open", "close", "search",
}
BLOCK_WORDS = {
    "cart", "basket", "bag", "checkout", "purchase", "buy", "order",
    "submit", "add to cart", "add to bag", "wishlist", "account", "login",
    "sign in", "delete", "remove", "pay",
}

def _norm(value):
    return " ".join((value or "").lower().split())

def _risk_word(value):
    text = _norm(value)
    if any(x in text for x in BLOCK_WORDS):
        return True
    return False

def _safe_toggle(value):
    text = _norm(value)
    return not _risk_word(text) and any(x in text for x in SAFE_TOGGLE_WORDS)

OBSERVE_JS = r'''
() => {
  const text=e=>(e.innerText||e.textContent||"").replace(/\s+/g," ").trim();
  const name=e=>{
    const a=e.getAttribute("aria-label"); if(a&&a.trim()) return a.trim();
    const ids=(e.getAttribute("aria-labelledby")||"").split(/\s+/).filter(Boolean);
    const labelled=ids.map(id=>document.getElementById(id)).filter(Boolean).map(text).filter(Boolean).join(" ");
    if(labelled) return labelled;
    if(e.tagName==="INPUT"||e.tagName==="TEXTAREA"||e.tagName==="SELECT"){
      if(e.labels&&e.labels.length){const x=[...e.labels].map(text).filter(Boolean).join(" ");if(x)return x;}
      if(e.getAttribute("placeholder")) return e.getAttribute("placeholder");
    }
    return text(e)||e.getAttribute("title")||"";
  };
  const visible=e=>{
    if(e.closest("[hidden],template,noscript,[aria-hidden='true']")) return false;
    const s=getComputedStyle(e);
    return s.display!=="none" && s.visibility!=="hidden" && parseFloat(s.opacity||"1")>0;
  };
  const focusable=e=>{
    if(!visible(e)||e.disabled||e.getAttribute("aria-disabled")==="true") return false;
    const ti=e.getAttribute("tabindex");
    if(ti!==null){const n=Number(ti);return Number.isFinite(n)&&n>=0;}
    const t=e.tagName.toLowerCase();
    return ["a","button","input","select","textarea","summary"].includes(t) &&
      (t!=="a"||e.hasAttribute("href"));
  };
  const interactive=[...document.querySelectorAll("a[href],button,input,select,textarea,summary,[tabindex],[role='button'],[role='link'],[role='checkbox'],[role='radio'],[role='combobox'],[role='tab'],[role='switch']")].filter(visible);
  const controls=interactive.map(e=>({
    tag:e.tagName.toLowerCase(),
    role:e.getAttribute("role")||"",
    name:name(e),
    disabled:!!e.disabled||e.getAttribute("aria-disabled")==="true",
    tabindex:e.getAttribute("tabindex"),
    expanded:e.getAttribute("aria-expanded"),
    controls:e.getAttribute("aria-controls"),
    haspopup:e.getAttribute("aria-haspopup"),
    id:e.id||"",
  }));
  return {
    controls,
    dialogs:[...document.querySelectorAll("[role='dialog'],dialog,[aria-modal='true']")].filter(visible).length,
    focusableCount:interactive.filter(focusable).length,
    title:document.title,
    url:location.href
  };
}
'''

KEYBOARD_JS = r'''
async ({steps}) => {
  const out=[];
  for(let i=0;i<steps;i++){
    document.body?.dispatchEvent(new Event("a11yforge:keyboard-probe",{bubbles:true}));
    const active=document.activeElement;
    if(!active){out.push({index:i,tag:null,name:"",visible:false,outline:""});continue;}
    const s=getComputedStyle(active);
    const rect=active.getBoundingClientRect();
    out.push({
      index:i,
      tag:active.tagName.toLowerCase(),
      name:(active.innerText||active.getAttribute("aria-label")||active.getAttribute("title")||"").replace(/\s+/g," ").trim().slice(0,160),
      id:active.id||"",
      visible:rect.width>0&&rect.height>0&&s.visibility!=="hidden",
      outline:[s.outlineStyle,s.outlineWidth,s.outlineColor].join(" "),
      boxShadow:s.boxShadow,
      tabindex:active.getAttribute("tabindex")
    });
    active.dispatchEvent(new KeyboardEvent("keydown",{key:"Tab",bubbles:true}));
    active.dispatchEvent(new KeyboardEvent("keyup",{key:"Tab",bubbles:true}));
  }
  return out;
}
'''

def _finding(rule, impact, observation, evidence, viewport):
    return {
        "rule": rule,
        "base_rule": rule,
        "axe": None,
        "sc": ["2.1.1"] if "keyboard" in rule or "focus" in rule else ["4.1.2"],
        "level": "A",
        "impact": impact,
        "observation": "browser_interaction",
        "signature": f"interaction|{rule}|{viewport}",
        "occurrence": 0,
        "snippet": "",
        "context": "",
        "name_evidence": evidence,
        "interaction_evidence": evidence,
        "evidence": evidence,
        "viewport": viewport,
        "scanner_version": INTERACTION_VERSION,
        "reproducible_with_axe": False,
    }

def audit(url, timeout_ms=15000, settle_ms=800):
    from playwright.sync_api import sync_playwright
    initial_host=(urlsplit(url).hostname or "").lower().rstrip(".")
    findings=[]
    evidence={"status":"OK","url":url,"viewports":[],"version":INTERACTION_VERSION}
    with sync_playwright() as p:
        browser=p.chromium.launch(headless=True,args=["--disable-dev-shm-usage"])
        context=browser.new_context(ignore_https_errors=True,service_workers="block",locale="en-US")
        for width,height in ((1440,1000),(390,844)):
            page=context.new_page()
            page.set_viewport_size({"width":width,"height":height})
            vp=f"{width}x{height}"
            try:
                def guard(route):
                    target=route.request.url
                    if target.startswith(("data:","blob:","about:")):
                        route.continue_(); return
                    try:
                        host=(urlsplit(target).hostname or "").lower().rstrip(".")
                        if host==initial_host or (host and is_public_url(target)):
                            route.continue_()
                        else:
                            route.abort()
                    except Exception:
                        route.abort()
                page.route("**/*",guard)
                response=page.goto(url,wait_until="domcontentloaded",timeout=timeout_ms)
                page.wait_for_timeout(settle_ms)
                page.evaluate("window.scrollTo(0, document.body ? document.body.scrollHeight : 0)")
                page.wait_for_timeout(500)
                page.evaluate("window.scrollTo(0,0)")
                data=page.evaluate(OBSERVE_JS)
                accessibility_tree={}
                try:
                    cdp=context.new_cdp_session(page)
                    ax=cdp.send("Accessibility.getFullAXTree")
                    nodes=ax.get("nodes",[])
                    interactive_ax=[n for n in nodes if n.get("role",{}).get("value") in {"button","link","textbox","combobox","checkbox","radio","switch","slider","tab","menuitem"}]
                    unnamed=[n for n in interactive_ax if not str(n.get("name",{}).get("value","")).strip() and not n.get("ignored")]
                    accessibility_tree={"status":"OK","node_count":len(nodes),"interactive_count":len(interactive_ax),"unnamed_interactive_count":len(unnamed),"unnamed_examples":[{"role":n.get("role",{}).get("value"),"backendDOMNodeId":n.get("backendDOMNodeId")} for n in unnamed[:10]]}
                except Exception as ax_exc:
                    accessibility_tree={"status":"ERROR","error":type(ax_exc).__name__+": "+str(ax_exc)[:300]}
                data["accessibility_tree"]=accessibility_tree
                controls=data.get("controls",[])
                for control in controls:
                    label=control.get("name","")
                    if control.get("expanded") is None and control.get("haspopup") is None:
                        continue
                    if not label:
                        findings.append(_finding("interactive-control-no-name","serious","interactive control has no accessible name",{"control":control},vp))
                    elif control.get("expanded") is not None and not control.get("controls"):
                        findings.append(_finding("expanded-control-missing-target","moderate","aria-expanded control has no aria-controls target",{"control":control},vp))
                # Keyboard traversal: focus is moved using real Playwright Tab events.
                sequence=[]
                for _ in range(min(60,max(10,int(data.get("focusableCount",0))+5))):
                    page.keyboard.press("Tab")
                    item=page.evaluate("""() => { const e=document.activeElement; if(!e)return null; const s=getComputedStyle(e); const r=e.getBoundingClientRect(); return {tag:e.tagName.toLowerCase(),name:(e.innerText||e.getAttribute('aria-label')||e.getAttribute('title')||'').replace(/\\s+/g,' ').trim().slice(0,160),id:e.id||'',visible:r.width>0&&r.height>0&&s.visibility!=='hidden',outline:[s.outlineStyle,s.outlineWidth,s.outlineColor].join(' '),shadow:s.boxShadow,tabindex:e.getAttribute('tabindex')}; }""")
                    if item: sequence.append(item)
                visible_focus=[x for x in sequence if x.get("visible")]
                no_indicator=[x for x in visible_focus if x.get("outline","").startswith("none") and x.get("shadow","none")=="none"]
                if visible_focus and len(no_indicator)>=max(3,len(visible_focus)//2):
                    findings.append(_finding("keyboard-focus-indicator","serious","most sampled keyboard-focused elements expose no visible focus indicator",{"sampled":len(visible_focus),"no_indicator":len(no_indicator),"examples":no_indicator[:5]},vp))
                # Detect focus traps or loops in the sampled sequence.
                keys=[(x.get("tag"),x.get("id"),x.get("name")) for x in visible_focus]
                if len(keys)>=12 and len(set(keys))<=3:
                    findings.append(_finding("keyboard-focus-loop","serious","keyboard traversal repeatedly cycles through a very small focus set",{"sampled":len(keys),"unique":len(set(keys)),"sequence":keys[:20]},vp))
                # Probe only strongly classified disclosure controls. Never click transactional controls.
                safe_probe_count=0
                for control in controls:
                    label=control.get("name","")
                    if safe_probe_count>=8 or not _safe_toggle(label): continue
                    locator=None
                    if control.get("id"):
                        locator=page.locator("#"+control["id"]).first
                    else:
                        locator=page.get_by_role("button",name=label,exact=True).first if label else None
                    if not locator: continue
                    try:
                        if not locator.is_visible(timeout=300): continue
                        before=locator.get_attribute("aria-expanded")
                        if before is None and control.get("haspopup") is None: continue
                        locator.click(timeout=1200)
                        page.wait_for_timeout(250)
                        after=locator.get_attribute("aria-expanded")
                        if before is not None and after==before:
                            findings.append(_finding("disclosure-control-no-state-change","moderate","safe disclosure control did not expose a state change after activation",{"name":label,"before":before,"after":after},vp))
                        safe_probe_count+=1
                    except Exception:
                        continue
                evidence["viewports"].append({"viewport":vp,"http_status":response.status if response else None,"url":page.url,"title":data.get("title",""),"interactive_count":len(controls),"focusable_count":data.get("focusableCount",0),"keyboard_samples":len(sequence),"safe_probes":safe_probe_count,"accessibility_tree":accessibility_tree})
            except Exception as exc:
                evidence["status"]="PARTIAL" if evidence["viewports"] else "ERROR"
                evidence.setdefault("errors",[]).append({"viewport":vp,"error":type(exc).__name__+": "+str(exc)[:300]})
            finally:
                page.close()
        context.close()
        browser.close()
    evidence["accessibility_tree"]={"viewports":[v.get("accessibility_tree",{}) for v in evidence.get("viewports",[])],"status":"OK" if any(v.get("accessibility_tree",{}).get("status")=="OK" for v in evidence.get("viewports",[])) else "ERROR"}
    evidence["finding_count"]=len(findings)
    return findings,evidence
