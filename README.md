# A11yForge v1.6.0

Accessibility intelligence, verification and conservative repair engine for ecommerce.

Formerly ShopScan. Product model:

**Discover → Verify → Repair → Regression-test → Evidence**

Static candidates are repeat-load verified, then checked in Chromium at desktop and mobile viewports. An adversarial simulation lab exercises malformed, dynamic and hostile inputs. The repair engine only applies deterministic low-risk transforms and never invents semantic copy.

A11yForge does not claim WCAG conformance, legal compliance, certification, or lawsuit protection. It does not mutate a live merchant store without an explicit authorized deployment integration.

## Current product phases

- **Phase 1:** consent-first scanning and domain ownership verification.
- **Phase 2:** Overlay Truth Test with deterministic evidence and per-finding hashes.
- **Phase 3:** developer-ready fix packs with human review before release.
- Later phases cover agency workspaces, monitoring/regression, quality review, and billing interface.

## Safety and delivery boundary

- Public preview scanning is disabled by default and requires explicit configuration.
- Full multi-page scans require verified domain authorization.
- Scans respect robots.txt, identify themselves with an A11yForge User-Agent, and apply per-host delays.
- Human approval is required before a client-facing report is released.
- Source patches are artifacts only. A11yForge never deploys changes to a live store without an authorized deployment integration.
- Every evidence report is labeled: **Evidence report, not legal advice or certification.**

## Development

Run the test suite with:

`python -m pytest -q`

The standalone 100-customer adversarial simulation is run separately because it requires Playwright:

`PYTHONPATH=. python simulation/test_100_customers.py`
