"""Post-repair regression verification.

Every source patch gets re-analyzed before it is presented as a successful remediation.
This never claims browser-level proof; it proves only that the deterministic source rule
no longer reproduces in the patched artifact.
"""
from scan import analyze

def verify_patch(before_html, after_html, repairs):
    before = analyze(before_html, "https://a11yforge.local/before")
    after = analyze(after_html, "https://a11yforge.local/after")
    before_keys={(f.get("base_rule") or f.get("rule"), f.get("signature")) for f in before.get("findings",[])}
    after_keys={(f.get("base_rule") or f.get("rule"), f.get("signature")) for f in after.get("findings",[])}
    checks=[]
    for repair in repairs or []:
        rule=repair.get("rule","")
        signature=repair.get("signature")
        remaining=signature in {s for r,s in after_keys} if signature else any(r==rule for r,_ in after_keys)
        checks.append({
            "rule":rule,
            "signature":signature,
            "status":"REGRESSION_CLEAN" if not remaining else "REGRESSION_REMAINS",
            "remaining":remaining,
        })
    return {
        "status":"CLEAN" if all(x["status"]=="REGRESSION_CLEAN" for x in checks) else "REMAINS",
        "checks":checks,
        "before_findings":len(before.get("findings",[])),
        "after_findings":len(after.get("findings",[])),
        "before_rules":sorted({r for r,_ in before_keys}),
        "after_rules":sorted({r for r,_ in after_keys}),
    }
