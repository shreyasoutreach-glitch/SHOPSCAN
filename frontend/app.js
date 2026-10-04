const API = window.A11YFORGE_API || "https://a11yforge-api-docker.onrender.com";
const routes={dashboard:"Overview",scan:"New scan",findings:"Findings",evidence:"Evidence",repairs:"Repairs"};
const title=document.getElementById("page-title");
const form=document.getElementById("scan-form");
const status=document.getElementById("scan-status");
const result=document.getElementById("scan-result");
const submit=document.getElementById("scan-submit");
let lastScan=loadScan();

function loadScan(){try{return JSON.parse(localStorage.getItem("a11yforge:lastScan")||"null")}catch{return null}}
function saveScan(data){
  lastScan=data;
  try{
    const persisted=JSON.parse(JSON.stringify(data));
    if(persisted.repair) delete persisted.repair.html;
    localStorage.setItem("a11yforge:lastScan",JSON.stringify(persisted));
  }catch{}
}
function currentRoute(){const r=location.hash.replace("#","");return routes[r]?r:"dashboard"}
function renderRoute(){
  const r=currentRoute();
  Object.keys(routes).forEach(k=>document.getElementById("view-"+k)?.classList.toggle("hidden",k!==r));
  document.querySelectorAll("nav a").forEach(a=>a.classList.toggle("active",a.dataset.route===r));
  title.textContent=routes[r];
  if(r==="findings") renderFindings();
  if(r==="evidence") renderEvidence();
  if(r==="repairs") renderRepairs();
  renderDashboard();
}
window.addEventListener("hashchange",renderRoute);
renderRoute();

form?.addEventListener("submit",async e=>{
  e.preventDefault();
  const url=document.getElementById("url").value.trim();
  if(!url)return;
  setBusy(true);
  status.className="status loading";
  status.textContent="Fetching source, verifying hydrated DOM and building evidence...";
  result.className="hidden";
  try{
    const res=await fetch(API+"/api/scan",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url})});
    const raw=await res.text();
    let data; try{data=JSON.parse(raw)}catch{throw new Error("The API returned an invalid response. Check the backend deployment.")};
    if(!res.ok)throw new Error(data.detail||"Scan failed");
    saveScan(data);
    status.className="status";
    status.textContent=data.result?.rendered_status==="OK"?"Verified scan complete.":"Scan complete with browser verification status: "+(data.result?.rendered_status||"unknown");
    renderResult(data);
    renderRoute();
  }catch(err){
    status.className="status error";
    status.textContent=err.message||"The scan failed safely. Try another public URL.";
  }finally{setBusy(false)}
});

function setBusy(b){
  if(!submit)return;
  submit.disabled=b;
  submit.textContent=b?"Verifying…":"Run verified scan";
}

function renderDashboard(){
  const domain=document.getElementById("dashboard-domain"), meta=document.getElementById("dashboard-scan-meta"), count=document.getElementById("finding-count");
  const findings=getFindings();
  if(count)count.textContent=findings.length;
  if(domain)domain.textContent=lastScan?.result?.domain||"None";
  if(meta)meta.textContent=lastScan?findings.length+" verified findings · "+(lastScan.result?.rendered_status||"verified"):"Run a verified assessment";
}

function getFindings(){return lastScan?.package?.work_queue||[]}
function getCandidates(){return lastScan?.package?.candidate_work_queue||lastScan?.result?.candidate_findings||[]}

function renderResult(data){
  const r=data.result||{}, findings=getFindings(), candidates=getCandidates(), display=findings.length?findings:candidates;
  const score=findings.reduce((n,f)=>n+(f.impact==='critical'?14:f.impact==='serious'?9:f.impact==='moderate'?5:1),0);
  result.className='result-card card';
  const limited=r.rendered_status&&r.rendered_status!=='OK';
  const label=limited?'ASSESSMENT WITH VERIFICATION LIMIT':'VERIFIED ASSESSMENT';
  const copy=limited?(candidates.length+' static candidates retained for remediation; browser verification is '+escapeHtml(r.rendered_status||'limited')):(findings.length+' verified findings');
  result.innerHTML='<div class="result-top"><div><span class="eyebrow">'+label+'</span><h3>'+escapeHtml(r.domain||r.url||'Merchant')+'</h3><p class="muted">'+copy+'</p></div><div><span class="eyebrow">RISK POINTS</span><div class="score">'+score+'</div></div></div>'+
    '<div class="result-actions"><a class="button primary" href="#findings">View '+display.length+' '+(findings.length?'findings':'candidates')+'</a><a class="button" href="#evidence">Open evidence</a><a class="button" href="#repairs">Open repairs</a><button class="button" id="rescan-button" type="button">Scan another store</button></div>'+
    '<div style="margin-top:20px">'+(display.length?display.map(f=>findingMarkup(f)).join(''):'<div class="empty"><h2>No accessibility candidates</h2><p>The current rule engine found nothing in scope.</p></div>')+'</div>';
  document.getElementById('rescan-button')?.addEventListener('click',()=>{location.hash='scan';document.getElementById('url')?.focus()});
}
function findingMarkup(f,i){
  const evidence=f.evidence||f.rendered_evidence||{};
  return '<article class="finding card" data-index="'+i+'"><div class="finding-main"><div class="sev">'+escapeHtml(f.impact||"moderate")+'</div><div><p class="finding-rule">'+escapeHtml(f.rule||f.base_rule||"Accessibility finding")+'</p><code>'+escapeHtml((f.snippet||"No source snippet retained").slice(0,240))+'</code></div><div class="priority">Priority '+escapeHtml(f.priority_score??"review")+'</div></div><div class="finding-detail"><span>Confidence: '+escapeHtml(f.confidence||"verified")+'</span><span>Action: '+escapeHtml(f.action||"review")+'</span><span>Evidence: '+escapeHtml(evidence.status||"browser verified")+'</span><button class="button small copy-finding" type="button">Copy finding</button></div></article>';
}

function renderFindings(){
  const el=document.getElementById("findings-list"), findings=getFindings();
  if(!lastScan){el.innerHTML='<div class="empty card"><span class="eyebrow">NO ACTIVE SCAN</span><h2>Nothing to review yet</h2><p>Run a verified scan first. Findings will populate this queue automatically.</p><a class="button primary" href="#scan">Start scan</a></div>';return}
  if(!findings.length){const candidates=getCandidates();if(!candidates.length){el.innerHTML='<div class="empty card"><span class="eyebrow">CLEAN VERIFICATION</span><h2>No verified findings</h2><p>No candidate was found in the current scan scope.</p></div>';return}el.innerHTML='<div class="status error">Browser verification is limited. These are static candidates, not verified findings.</div>'+candidates.map((f,i)=>findingMarkup(f,i)).join('');return}
  el.innerHTML=findings.map((f,i)=>findingMarkup(f,i)).join("");
  el.querySelectorAll(".copy-finding").forEach((btn,i)=>btn.addEventListener("click",async()=>{
    const f=findings[i];
    const text="A11yForge finding\nRule: "+(f.rule||f.base_rule)+"\nImpact: "+(f.impact||"moderate")+"\nPriority: "+(f.priority_score??"review")+"\nSnippet: "+(f.snippet||"");
    try{await navigator.clipboard.writeText(text);btn.textContent="Copied";setTimeout(()=>btn.textContent="Copy finding",1200)}catch{btn.textContent="Copy failed"}
  }));
}

function renderRepairs(){
  const el=document.getElementById("repairs-list");
  if(!lastScan){el.innerHTML='<div class="empty card"><span class="eyebrow">NO ACTIVE SCAN</span><h2>Nothing to repair yet</h2><p>Run a verified scan first.</p><a class="button primary" href="#scan">Start scan</a></div>';return}
  const repairs=lastScan.repair?.repairs||lastScan.package?.repairs||[], proposals=lastScan.repair?.proposals||lastScan.package?.review_queue||[];
  let html='<div class="repair-summary"><div class="card"><span>Safe repairs</span><strong>'+repairs.length+'</strong><small>Deterministic source transforms</small></div><div class="card"><span>Review required</span><strong>'+proposals.length+'</strong><small>Semantic meaning cannot be safely invented</small></div></div>';
  html+='<div class="card repair-panel"><div class="card-head"><div><span class="eyebrow">PATCH ARTIFACT</span><h3>Generated source repair</h3></div><span class="tag">'+(repairs.length?'READY':'NO SAFE PATCHES')+'</span></div>';
  html+='<p class="muted">'+(repairs.length?'The engine generated deterministic changes from verified findings. This is a patch artifact, not a live Shopify deployment.':'No verified finding in this scan had a safe deterministic source transform.')+'</p>';
  if(repairs.length) html+='<div class="repair-list">'+repairs.map(x=>'<div class="repair-row"><strong>'+escapeHtml(x.rule||"repair")+'</strong><span>'+escapeHtml(x.action||"safe repair")+'</span><code>'+escapeHtml(x.signature||"")+'</code></div>').join("")+'</div>';
  if(proposals.length) html+='<details class="review-box"><summary>'+proposals.length+' review items</summary><pre>'+escapeHtml(JSON.stringify(proposals,null,2))+'</pre></details>';
  html+='<div class="result-actions">'+(repairs.length&&typeof lastScan.repair?.html==="string"?'<button class="button primary" id="download-repair" type="button">Download patched HTML</button>':'')+'<a class="button" href="#findings">Open findings</a></div></div>';
  el.innerHTML=html;
  document.getElementById("download-repair")?.addEventListener("click",()=>{
    const source=lastScan.repair?.html;
    if(typeof source!=="string")return;
    const blob=new Blob([source],{type:"text/html;charset=utf-8"});
    const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="a11yforge-"+(lastScan.scan_id||"scan")+"-patched.html";a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);
  });
}

function renderEvidence(){
  const el=document.getElementById("evidence-list");
  if(!lastScan){el.innerHTML='<div class="empty card"><span class="eyebrow">NO LEDGER</span><h2>No scan evidence yet</h2><p>Run a scan to create a retained evidence record.</p><a class="button primary" href="#scan">Start scan</a></div>';return}
  const r=lastScan.result||{}, findings=getFindings(), candidates=getCandidates(), evidence=r.rendered_evidence||r.evidence||{};
  el.innerHTML='<div class="card evidence-card"><div class="card-head"><div><span class="eyebrow">SCAN RECORD</span><h3>'+escapeHtml(r.domain||r.url||"Merchant")+'</h3></div><span class="tag">'+escapeHtml(r.rendered_status||"VERIFIED")+'</span></div><div class="evidence-grid">'+
    '<div><span>Scan ID</span><strong>'+escapeHtml(lastScan.scan_id||"n/a")+'</strong></div>'+
    '<div><span>Final URL</span><strong>'+escapeHtml(evidence.final_url||r.url||"n/a")+'</strong></div>'+
    '<div><span>Findings</span><strong>'+findings.length+'</strong></div>'+
    '<div><span>HTTP status</span><strong>'+escapeHtml(evidence.http_status||"n/a")+'</strong></div>'+
    '</div><details><summary>Raw evidence</summary><pre>'+escapeHtml(JSON.stringify({result:r,findings},null,2))+'</pre></details><div class="result-actions"><button class="button primary" id="download-evidence" type="button">Export evidence JSON</button><a class="button" href="#findings">Open findings</a></div></div>';
  document.getElementById("download-evidence")?.addEventListener("click",()=>{
    const blob=new Blob([JSON.stringify(lastScan,null,2)],{type:"application/json"});
    const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="a11yforge-"+(lastScan.scan_id||"scan")+".json";a.click();URL.revokeObjectURL(a.href);
  });
}

function escapeHtml(v){return String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]))}
