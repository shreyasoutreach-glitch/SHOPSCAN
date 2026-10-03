"""Browser-backed rendered DOM verification for ShopScan."""
from rendered import RenderedVerifier, CONFIRMED, NOT_REPRODUCED, ERROR

JS = r'''
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
  const visible=e=>{if(e.closest('[hidden],template,noscript,[aria-hidden="true"]'))return false;const s=getComputedStyle(e);return s.display!=='none'&&s.visibility!=='hidden'};
  const named=e=>{
    const a=e.getAttribute('aria-label'); if(a&&a.trim())return true;
    const r=e.getAttribute('aria-labelledby'); if(r&&r.split(/\s+/).some(id=>{const x=document.getElementById(id);return x&&x.textContent.trim()}))return true;
    if(e.id&&[...document.querySelectorAll('label')].some(x=>x.htmlFor===e.id))return true;
    if(e.closest('label'))return true;
    if(e.tagName==='IMG')return e.hasAttribute('alt');
    if(e.tagName==='IFRAME'||e.tagName==='FRAME')return !!e.getAttribute('title')?.trim();
    return !!e.textContent?.trim()||!!e.getAttribute('title')?.trim()||!!e.getAttribute('value')?.trim();
  };
  const matches=r=>[...document.querySelectorAll('*')].filter(e=>{
    if(!visible(e))return false; const t=e.tagName.toLowerCase();
    if(r==='image-alt')return t==='img'&&!e.hasAttribute('alt');
    if(r==='label')return ['input','textarea','select'].includes(t)&&!(t==='input'&&['hidden','submit','reset','button','image'].includes((e.getAttribute('type')||'text').toLowerCase()))&&!named(e);
    if(r==='button-name')return t==='button'&&!named(e);
    if(r==='link-name')return t==='a'&&e.hasAttribute('href')&&!named(e);
    if(r==='frame-title')return(t==='iframe'||t==='frame')&&!named(e);
    if(r==='html-has-lang')return t==='html'&&!((e.getAttribute('lang')||e.getAttribute('xml:lang')||'').trim());
    if(r==='document-title')return t==='html'&&!document.title.trim();if(r==='meta-viewport'){if(t!=='meta'||(e.getAttribute('name')||'').toLowerCase()!=='viewport')return false;const c=(e.getAttribute('content')||'').toLowerCase();return /user-scalable\\s*=\\s*(no|0)\\b/.test(c)||/(^|[;,]\\s*)maximum-scale\\s*=\\s*[0-9.]+/.test(c)&&Number((c.match(/maximum-scale\\s*=\\s*([0-9.]+)/)||[])[1]||99)<=1}
    return false;
  });
  const seen=new Map();
  for(const r of ['image-alt','label','button-name','link-name','frame-title','html-has-lang','document-title','meta-viewport'])
    for(const e of matches(r)){const s=r+'|'+e.tagName.toLowerCase()+'|'+shape(e);seen.set(s,(seen.get(s)||0)+1)}
  return candidates.map(c=>({signature:c.signature,occurrence:c.occurrence,found:(seen.get(c.signature)||0)>Number(c.occurrence||0)}));
}
''';

class PlaywrightVerifier(RenderedVerifier):
    name = "playwright-dom"

    def __init__(self, timeout_ms=20000, settle_ms=1200, headless=True):
        self.timeout_ms, self.settle_ms, self.headless = timeout_ms, settle_ms, headless

    def verify(self, url, findings):
        if not findings:
            return {}
        try:
            from playwright.sync_api import sync_playwright
        except Exception:
            return {(f["signature"], f["occurrence"]): ERROR for f in findings}
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=self.headless)
                page = browser.new_page(viewport={"width": 1440, "height": 1000})
                page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
                page.wait_for_timeout(self.settle_ms)
                candidates = [{"signature": f["signature"], "occurrence": f["occurrence"]} for f in findings]
                result = page.evaluate(JS, candidates)
                browser.close()
            return {(r["signature"], r["occurrence"]): (CONFIRMED if r["found"] else NOT_REPRODUCED) for r in result}
        except Exception:
            return {(f["signature"], f["occurrence"]): ERROR for f in findings}
