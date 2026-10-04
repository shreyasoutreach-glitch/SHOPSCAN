"""Client-facing accessibility assessment and remediation packaging.

Turns verified findings into an ordered work queue and evidence package.
It never claims legal compliance and never mutates a merchant's live store.
"""
from datetime import datetime, timezone

SEVERITY={"critical":4,"serious":3,"moderate":2,"minor":1}

def prioritize(findings):
    out=[]
    for f in findings:
        impact=f.get("impact","moderate")
        score=SEVERITY.get(impact,1)
        rule=f.get("base_rule") or f.get("rule","unknown")
        # Purchase-path semantics get a multiplier when the scanner supplies it.
        surface=f.get("surface","")
        if surface in {"cart","checkout","product"}: score+=2
        out.append({**f,"priority_score":score})
    return sorted(out,key=lambda x:(-x["priority_score"],x.get("off",0)))

def build_client_package(scan_result, repair_result=None):
    findings=prioritize(scan_result.get("findings",[]))
    proposals=(repair_result or {}).get("proposals",[])
    repairs=(repair_result or {}).get("repairs",[])
    return {
        "product":"A11yForge",
        "generated_at":datetime.now(timezone.utc).isoformat(),
        "merchant":scan_result.get("domain"),
        "assessment_scope":{
            "url":scan_result.get("url"),
            "verified_loads":scan_result.get("verified_loads",0),
            "rendered_status":scan_result.get("rendered_status"),
            "rendered_evidence":scan_result.get("rendered_evidence",{}),
            "limitations":scan_result.get("limitations",[]),
        },
        "executive_summary":{
            "verified_findings":len(findings),
            "safe_repairs_available":len(repairs),
            "human_review_items":len(proposals),
            "confidence_boundary":"Findings are verified observations within the stated scan scope, not a WCAG certification or legal opinion."
        },
        "work_queue":findings,
        "repairs":repairs,
        "review_queue":proposals,
        "acceptance_plan":[
            "Apply reviewed repairs in a staging theme.",
            "Re-run the same browser verification at desktop and mobile viewports.",
            "Re-test affected purchase and navigation interactions.",
            "Record before/after evidence and retain the regression result."
        ]
    }
