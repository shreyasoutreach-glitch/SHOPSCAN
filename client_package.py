"""Client-facing evidence and developer fix-pack packaging.

Reports are evidence artifacts, not legal advice or certification. Release is gated on
explicit human approval. Source patches are suggestions only and never deployed.
"""
import difflib
import html
import io
import json
from copy import deepcopy
from datetime import datetime, timezone

SEVERITY={"critical":4,"serious":3,"moderate":2,"minor":1}
EXPLANATIONS={
    "image-alt":"An image element does not provide a usable text alternative.",
    "label":"A form control does not expose a usable accessible label.",
    "button-name":"A button does not expose a usable accessible name.",
    "link-name":"A link does not expose a usable accessible name.",
    "frame-title":"A frame does not expose a usable title.",
    "html-has-lang":"The document does not declare its primary language.",
    "document-title":"The document does not expose a meaningful title.",
    "meta-viewport":"The viewport metadata restricts user zooming.",
    "duplicate-id":"Multiple elements reuse the same id, which can break programmatic relationships.",
    "aria-reference":"An ARIA ID reference points to an element that does not exist.",
    "aria-hidden-focusable":"Focusable content is hidden from assistive technologies.",
    "empty-aria-label":"An interactive element has an empty aria-label.",
}
REPORT_FOOTER="Evidence report, not legal advice or certification."

def prioritize(findings):
    out=[]
    for f in findings:
        impact=f.get("impact","moderate")
        score=SEVERITY.get(impact,1)
        surface=f.get("surface","")
        if surface in {"cart","checkout","product"}: score+=2
        out.append({**f,"priority_score":score})
    return sorted(out,key=lambda x:(-x["priority_score"],x.get("off",0)))

def _risk(f):
    return {"critical":"HIGH","serious":"HIGH","moderate":"MEDIUM","minor":"LOW"}.get(f.get("impact"),"MEDIUM")

def _patch_for(f,source_html):
    if not source_html or f.get("off") is None or not f.get("source_repairable",True):
        return {"status":"NEEDS HUMAN REVIEW","language":"html","diff":"","reason":"No deterministic source patch is available for this observation."}
    try:
        from repair import repair_html
        before=source_html
        result=repair_html(source_html,[f])
        if not result.get("changed"):
            return {"status":"NEEDS HUMAN REVIEW","language":"html","diff":"","reason":"No deterministic safe repair is available."}
        after=result.get("html",before)
        diff="".join(difflib.unified_diff(
            before[max(0,int(f.get("off",0))-180):int(f.get("off",0))+int(f.get("length",0))+180].splitlines(True),
            after[max(0,int(f.get("off",0))-180):int(f.get("off",0))+int(f.get("length",0))+180].splitlines(True),
            fromfile="theme-before.html",tofile="theme-after.html"
        ))
        return {"status":"SAFE_SUGGESTION","language":"shopify_theme_markup" if f.get("platform")=="shopify" else "html","diff":diff,"reason":"Deterministic source patch generated for review."}
    except Exception as exc:
        return {"status":"NEEDS HUMAN REVIEW","language":"html","diff":"","reason":type(exc).__name__+": "+str(exc)[:160]}

def build_fix_pack(findings,scan_result,source_html=None):
    platform=(scan_result.get("context") or {}).get("platform")
    rows=[]
    for f in prioritize(findings):
        f=dict(f)
        f["platform"]=platform
        rule=f.get("base_rule") or f.get("rule","unknown")
        patch=_patch_for(f,source_html)
        if patch["status"]=="SAFE_SUGGESTION":
            review="READY_FOR_DEVELOPER_REVIEW"
        else:
            review="NEEDS HUMAN REVIEW"
        rows.append({
            "page":f.get("source_page") or f.get("url") or scan_result.get("url"),
            "selector":f.get("path") or f.get("selector") or "(DOM selector not deterministically available)",
            "wcag_criterion_reference":f.get("sc",[]),
            "rule":rule,
            "risk_level":_risk(f),
            "plain_english_explanation":EXPLANATIONS.get(rule,"This verified observation requires developer review."),
            "evidence_hash":f.get("evidence_hash"),
            "dom_snippet":f.get("snippet") or f.get("context") or (f.get("evidence") or {}).get("outer",""),
            "patch":patch,
            "review_status":review,
        })
    return rows

def build_client_package(scan_result, repair_result=None, source_html=None):
    findings=prioritize(scan_result.get("findings",[]))
    proposals=(repair_result or {}).get("proposals",[])
    overlay=scan_result.get("overlay_evidence",{})
    interaction=scan_result.get("interaction_evidence",{})
    repairs=(repair_result or {}).get("repairs",[])
    fix_pack=build_fix_pack(findings,scan_result,source_html)
    return {
        "product":"A11yForge",
        "generated_at":datetime.now(timezone.utc).isoformat(),
        "merchant":scan_result.get("domain"),
        "report_disclaimer":REPORT_FOOTER,
        "release_gate":{"status":"PENDING_HUMAN_APPROVAL","approved_by":None,"approved_at":None},
        "assessment_scope":{
            "url":scan_result.get("url"),"verified_loads":scan_result.get("verified_loads",0),
            "rendered_status":scan_result.get("rendered_status"),"assessment_status":scan_result.get("assessment_status"),
            "candidate_count":len(scan_result.get("candidate_findings",[])),
            "rendered_evidence":scan_result.get("rendered_evidence",{}),
            "limitations":scan_result.get("limitations",[]),"overlay_truth_test":overlay,
            "evidence_head_hash":scan_result.get("evidence_head_hash"),
        },
        "executive_summary":{
            "verified_findings":len(findings),"safe_repairs_available":len(repairs),
            "human_review_items":len(proposals)+sum(x["review_status"]=="NEEDS HUMAN REVIEW" for x in fix_pack),
            "verified_interaction_findings":len(scan_result.get("interaction_findings",[])),
            "overlay_vendors":[x.get("vendor") for x in overlay.get("runtime",[]) if x.get("vendor")],
            "confidence_boundary":"Verified findings are browser-confirmed observations. Static candidates retained under a verification limit are explicitly unverified and require confirmation before being treated as proven defects."
        },
        "work_queue":findings,
        "candidate_work_queue":prioritize(scan_result.get("candidate_findings",[])),
        "overlay_truth_test":{
            "vendors":overlay.get("runtime",[]),"source_signals":overlay.get("source",[]),
            "remaining_verified_findings":len(overlay.get("truth_test",{}).get("remaining_in_both",[])),
            "interaction_findings":len(scan_result.get("interaction_findings",[])),
            "accessibility_tree":interaction.get("accessibility_tree",{})
        },
        "evidence_ledger":scan_result.get("evidence_ledger",{}),
        "developer_fix_pack":fix_pack,
        "repairs":repairs,
        "repair_regression":(repair_result or {}).get("regression",{"status":"NOT_RUN"}),
        "review_queue":proposals,
        "acceptance_plan":[
            "Review every suggested patch in a staging theme.",
            "Re-run the same browser verification at desktop and mobile viewports.",
            "Re-test affected purchase and navigation interactions.",
            "Record before/after evidence and retain the regression result."
        ]
    }

def approve_package(package,reviewer):
    reviewer=(reviewer or "").strip()
    if not reviewer: raise ValueError("A human reviewer name is required.")
    out=deepcopy(package)
    out["release_gate"]={"status":"APPROVED","approved_by":reviewer,"approved_at":datetime.now(timezone.utc).isoformat()}
    return out

def _require_approval(package):
    if (package.get("release_gate") or {}).get("status")!="APPROVED":
        raise PermissionError("Human approval is required before releasing this report.")

def export_json(package):
    _require_approval(package)
    return json.dumps(package,indent=2,sort_keys=True,ensure_ascii=False).encode("utf-8")

def _html_body(package):
    rows=[]
    for item in package.get("developer_fix_pack",[]):
        rows.append(
            "<article><h2>"+html.escape(item["rule"])+"</h2>"
            "<p><b>Page:</b> "+html.escape(str(item["page"]))+"</p>"
            "<p><b>Selector:</b> "+html.escape(str(item["selector"]))+"</p>"
            "<p><b>WCAG criterion reference:</b> "+html.escape(", ".join(item["wcag_criterion_reference"]))+"</p>"
            "<p><b>Risk:</b> "+html.escape(item["risk_level"])+"</p>"
            "<p>"+html.escape(item["plain_english_explanation"])+"</p>"
            "<pre>"+html.escape(item["dom_snippet"] or "")+"</pre>"
            "<h3>Suggested patch</h3><pre>"+html.escape(item["patch"]["diff"] or item["patch"]["reason"])+"</pre>"
            "<p><b>Review:</b> "+html.escape(item["review_status"])+"</p></article>"
        )
    gate=package.get("release_gate",{})
    return "<!doctype html><html><head><meta charset='utf-8'><title>A11yForge Evidence Report</title><style>body{font-family:system-ui;max-width:1000px;margin:40px auto;padding:0 24px;color:#111}article{border:1px solid #ddd;padding:20px;margin:18px 0;border-radius:12px}pre{white-space:pre-wrap;background:#f6f6f6;padding:12px;overflow:auto}footer{margin-top:40px;font-weight:700}.gate{padding:12px;background:#f6f6f6}</style></head><body><h1>A11yForge Evidence Report</h1><div class='gate'>Release approval: "+html.escape(str(gate.get("status")))+"</div>"+''.join(rows)+"<footer>"+REPORT_FOOTER+"</footer></body></html>"

def export_html(package):
    _require_approval(package)
    return _html_body(package).encode("utf-8")

def export_pdf(package):
    _require_approval(package)
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet,ParagraphStyle
    from reportlab.lib.enums import TA_LEFT
    from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Preformatted,PageBreak
    buffer=io.BytesIO()
    doc=SimpleDocTemplate(buffer,pagesize=A4,rightMargin=36,leftMargin=36,topMargin=36,bottomMargin=36)
    styles=getSampleStyleSheet()
    small=ParagraphStyle("small",parent=styles["BodyText"],fontSize=8,leading=10)
    story=[Paragraph("A11yForge Evidence Report",styles["Title"]),Paragraph(REPORT_FOOTER,styles["BodyText"]),Spacer(1,12)]
    for item in package.get("developer_fix_pack",[]):
        story.extend([
            Paragraph(html.escape(item["rule"]),styles["Heading2"]),
            Paragraph("Page: "+html.escape(str(item["page"])),small),
            Paragraph("Selector: "+html.escape(str(item["selector"])),small),
            Paragraph("WCAG criterion reference: "+html.escape(", ".join(item["wcag_criterion_reference"])),small),
            Paragraph("Risk: "+html.escape(item["risk_level"]),small),
            Paragraph(html.escape(item["plain_english_explanation"]),styles["BodyText"]),
            Preformatted(item["dom_snippet"] or "",small),
            Paragraph("Suggested patch: "+html.escape(item["patch"]["status"]),styles["Heading3"]),
            Preformatted(item["patch"]["diff"] or item["patch"]["reason"],small),
            Paragraph("Review: "+html.escape(item["review_status"]),small),
            Spacer(1,12)
        ])
    doc.build(story)
    return buffer.getvalue()
