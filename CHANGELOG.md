# Changelog\n\n## Unreleased / Phases 4-5\n\n### Phase 4\n- Added Postgres-backed agency workspaces and multi-client records.\n- Added configurable workspace client limits.\n- Added bulk CSV client onboarding.\n- Added per-client evidence-history dashboard endpoint.\n- Added seven-day expiring evidence share links with workspace branding.\n- Agency APIs require a separate agency key and never grant scan authorization.\n\n### Phase 5\n- Added evidence snapshots with deterministic finding fingerprints.\n- Added new/fixed/unchanged/regressed diff classification.\n- Added persisted monitoring events and target history.\n- Monitoring targets require pre-existing GRANTED domain authorization.\n- Added a protected due-target runner and scheduled GitHub Actions workflow.\n- Monitoring reuses the normal scan path so consent and scan safety controls are not bypassed.\n

## 1.6.0

### Phase 0
- Reconciled repository versioning to 1.6.0.
- Added GAP_REPORT.md.
- Restricted pytest collection to the real test suite and kept the Playwright simulation as a separate gate.
- Fixed CI test dependencies and documented known quality boundaries.

### Phase 1
- Added NOT_REQUESTED, REQUESTED, GRANTED and DECLINED domain authorization states.
- Added DNS TXT and homepage meta-tag ownership verification.
- Full multi-page scans now require GRANTED authorization.
- Added opt-out and operator do-not-scan enforcement.
- Added structured scan-request logging with a stateless logging fallback.
- Added a disabled-by-default limited public-preview mode with an explicit legal-review warning.
- Preserved robots.txt, User-Agent and rate-limit protections.

### Phase 2
- Added known overlay signature blocking for paired browser verification.
- Added Overlay Truth Test evidence showing findings that remain when detected overlay resources are blocked.
- Added deterministic per-finding evidence hashes.

### Phase 3
- Added developer-ready fix packs with page, selector, criterion reference, explanation, DOM evidence, risk and suggested diff.
- Ambiguous findings are marked NEEDS HUMAN REVIEW and are never auto-applied.
- Added human approval gating for HTML, PDF and JSON report exports.
- Added the required evidence-report disclaimer to released reports.
- Added PDF export using ReportLab 5.0.1.

## Release boundary

A11yForge reports are evidence artifacts, not legal advice or certification. A11yForge does not claim WCAG conformance, legal compliance, certification, or lawsuit protection.
