# Phase 0 Gap Report

## Baseline audit

Repository audited across the application, scanner, crawler, browser verifier, repair/regression modules, persistence, Shopify integration, frontend, tests, simulations, sales material and GitHub workflows.

The current CI run at commit `56da63b` failed during pytest collection because `simulation/test_100_customers.py` imports Playwright while the CI test job did not install Playwright. The failure is a test-boundary/dependency issue, not a scanner failure.

## Version reconciliation

Before Phase 0 the repository exposed four versions:
- README: 1.3
- pyproject: 1.3.0
- static scanner: 1.5.0
- frontend: 1.5
- API: 1.6.0

Phase 0 standardizes the product/scanner version to **1.6.0** and limits pytest collection to `tests/`. The standalone Playwright simulation remains a separate CI step.

## What works

- Static HTML analysis with deterministic findings and conservative semantic inference.
- Repeat-load verification.
- Chromium verification at desktop/mobile viewports.
- Read-only interaction probes with transactional controls excluded.
- robots.txt handling, public-IP/SSRF guards, bounded responses, retries and per-host delays.
- Overlay source/runtime signature detection.
- Tamper-evident evidence ledger.
- Conservative source repair with regression checks.
- Existing adversarial and 100-customer simulation infrastructure.

## Stubbed or incomplete for the business offer

- Domain authorization has no persisted state machine or owner verification.
- Full scans are currently callable from the public API without a verified-domain gate.
- Suppression/do-not-scan lists are not enforced as first-class scan policy.
- Scan requests are not persisted as authorization/audit events.
- Overlay detection does not yet perform a paired shipped-vs-blocked browser run.
- Findings have a document/evidence ledger hash, but no stable per-finding evidence hash.
- Client package is JSON-shaped data only. HTML/PDF export is not implemented.
- Fix output does not yet consistently provide page, selector, criterion, screenshot/DOM evidence, patch diff and explicit risk/review status.
- There is no mandatory human approval gate before client-facing release.
- No explicit report-release state exists.

## Untested / quality risks

- Domain ownership verification and DNS/meta authorization flows do not exist yet.
- Robots behavior has unit coverage only indirectly and needs policy tests around authorization.
- Overlay-blocked reruns need local fixture tests.
- Evidence reproducibility needs deterministic paired-run fixtures.
- Selector generation and patch-diff generation need fixture coverage.
- Browser screenshots are not currently part of client package generation.
- PDF generation and HTML report rendering are not currently tested.
- Multi-page evidence has limited coverage.
- Persistence is optional and there is no audit log for report approval.

## Known false-positive / false-negative risks

- Browser interaction heuristics can flag focus/disclosure behavior that requires human interpretation.
- Accessible-name inference intentionally skips uncertain cases, which creates false negatives in ambiguous markup.
- Overlay signatures are vendor-signature based and explicitly not exhaustive.
- Dynamic third-party content can vary between loads.
- Source findings can be valid while a hydrated UI changes the relevant DOM before verification.
- Platform/market detection is heuristic and must not be treated as proof.
- A source patch can remove a deterministic rule without proving that the resulting user experience is correct.

## Business readiness conclusion

The engine is suitable for controlled technical pilots after Phases 1-3 are shipped. It is **not yet ready for unrestricted public scanning or automatic client report release**.
