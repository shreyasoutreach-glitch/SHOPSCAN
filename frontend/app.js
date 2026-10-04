const API = window.A11YFORGE_API || "https://a11yforge-api-docker.onrender.com";
const routes={dashboard:"Overview",scan:"New scan",findings:"Findings",evidence:"Evidence"};
const title=document.getElementById("page-title");
const form=document.getElementById("scan-form");
const status=document.getElementById("scan-status");
const result=document.getElementById("scan-result");
const submit=document.getElementById("scan-submit");
let lastScan=loadScan();

function loadScan(){try{return JSON.parse(localStorage.getItem("a11yforge:lastScan")||"null")}catch{return null}}
function saveScan(data){lastScan=data;try{localStorage.setItem("a11yforge:lastScan",JSON.stringify(data))}catch{}}
function currentRoute(){const r=location.hash.replace("#","");return routes[r]?r:"dashboard"}
function renderRoute(){
  const r=currentRoute();
  Object.keys(routes).forEach(k=>document.getElementById("view-"+k)?.classList.toggle("hidden",k!==r));
  document.querySelectorAll("nav a").forEach(a=>a.classList.toggle("active",a.dataset.route===r));
  title.textContent=routes[r];
  if(r==="findings") renderFindings();
  if(r==="evidence") renderEvidence();
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
    status.textContent="Verified scan complete.";
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

function renderResult(data){
  const r=data.result||{}, findings=getFindings(), score=findings.reduce((n,f)=>n+(f.impact==="critical"?14:f.impact==="serious"?9:f.impact==="moderate"?5:1),0);
  result.className="result-card card";
  result.innerHTML='<div class="result-top"><div><span class="eyebrow">VERIFIED ASSESSMENT</span><h3>'+escapeHtml(r.domain||r.url||"Merchant")+'</h3><p class="muted">'+(r.rendered_status==="OK"?"Chromium verification passed":"Browser verification: "+escapeHtml(r.rendered_status||"unknown"))+" · "+findings.length+' verified findings</p></div><div><span class="eyebrow">RISK SIGNAL</span><div class="score">'+score+'</div></div></div>'+
    '<div class="result-actions"><a class="button primary" href="#findings">View '+findings.length+' findings</a><a class="button" href="#evidence">Open evidence</a><button class="button" id="rescan-button" type="button">Scan another store</button></div>'+
    '<div style="margin-top:20px">'+(findings.length?findings.map(f=>findingMarkup(f)).join(""):'<div class="empty"><h2>No verified findings</h2><p>The engine did not retain a finding after browser verification.</p></div>')+'</div>';
  document.getElementById("rescan-button")?.addEventListener("click",()=>{location.hash="scan";document.getElementById("url")?.focus()});
}

function findingMarkup(f,i){
  const evidence=f.evidence||f.rendered_evidence||{};
  return '<article class="finding card" data-index="'+i+'"><div class="finding-main"><div class="sev">'+escapeHtml(f.impact||"moderate")+'</div><div><p class="finding-rule">'+escapeHtml(f.rule||f.base_rule||"Accessibility finding")+'</p><code>'+escapeHtml((f.snippet||"No source snippet retained").slice(0,240))+'</code></div><div class="priority">Priority '+escapeHtml(f.priority_score??"review")+'</div></div><div class="finding-detail"><span>Confidence: '+escapeHtml(f.confidence||"verified")+'</span><span>Action: '+escapeHtml(f.action||"review")+'</span><span>Evidence: '+escapeHtml(evidence.status||"browser verified")+'</span><button class="button small copy-finding" type="button">Copy finding</button></div></article>';
}

function renderFindings(){
  const el=document.getElementById("findings-list"), findings=getFindings();
  if(!lastScan){el.innerHTML='<div class="empty card"><span class="eyebrow">NO ACTIVE SCAN</span><h2>Nothing to review yet</h2><p>Run a verified scan first. Findings will populate this queue automatically.</p><a class="button primary" href="#scan">Start scan</a></div>';return}
  if(!findings.length){el.innerHTML='<div class="empty card"><span class="eyebrow">CLEAN VERIFICATION</span><h2>No verified findings</h2><p>The browser verification gate rejected every candidate from this scan.</p></div>';return}
  el.innerHTML=findings.map((f,i)=>findingMarkup(f,i)).join("");
  el.querySelectorAll(".copy-finding").forEach((btn,i)=>btn.addEventListener("click",async()=>{
    const f=findings[i];
    const text="A11yForge finding\nRule: "+(f.rule||f.base_rule)+"\nImpact: "+(f.impact||"moderate")+"\nPriority: "+(f.priority_score??"review")+"\nSnippet: "+(f.snippet||"");
    try{await navigator.clipboard.writeText(text);btn.textContent="Copied";setTimeout(()=>btn.textContent="Copy finding",1200)}catch{btn.textContent="Copy failed"}
  }));
}

function renderEvidence(){
  const el=document.getElementById("evidence-list");
  if(!lastScan){el.innerHTML='<div class="empty card"><span class="eyebrow">NO LEDGER</span><h2>No scan evidence yet</h2><p>Run a scan to create a retained evidence record.</p><a class="button primary" href="#scan">Start scan</a></div>';return}
  const r=lastScan.result||{}, findings=getFindings(), evidence=r.rendered_evidence||r.evidence||{};
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
