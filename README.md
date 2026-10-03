# ShopScan v1.2

Networked accessibility prospecting scanner for Shopify stores.

## Verification pipeline

ShopScan uses a precision-first multi-stage model:

1. **Static source scan** identifies accessibility candidates from fetched HTML.
2. **Repeat-load verification** keeps only findings reproduced across two independent HTTP loads.
3. **Rendered verification** launches Chromium against the live URL and checks the hydrated DOM at desktop and mobile viewports after a settle + scroll cycle.
4. A finding is removed only when the browser explicitly fails to reproduce its stable signature. Browser failures remain visible as \`ERROR\`, never silently becoming clean results.

Rendered evidence records the final URL, HTTP status, DOM element count, document title, responsive viewport, page errors, console errors, and failed requests. This makes scan output auditable rather than just a list of guessed violations.

## Running the network scanner

\`\`\`bash
pip install -r requirements-rendered.txt
python -m playwright install --with-deps chromium
python network_runner.py
\`\`\`

Environment controls include \`SHOPSCAN_WORKERS\`, \`SHOPSCAN_DELAY\`, \`SHOPSCAN_MAX_BYTES\`, \`SHOPSCAN_RENDER_TIMEOUT_MS\`, \`SHOPSCAN_RENDER_SETTLE_MS\`, and \`SHOPSCAN_RENDERED=playwright|off\`.

## Confidence semantics

- \`CONFIRMED\`: candidate reproduced in the rendered browser DOM in at least one target viewport.
- \`NOT_REPRODUCED\`: candidate survived static repeat-load verification but was absent from the hydrated DOM in all target viewports.
- \`ERROR\`: browser verification could not complete. The finding is retained and marked as uncertain.
- \`NOT_RUN\`: rendered verification was explicitly disabled.

\`FOUND\` means there are retained candidates after the configured verification stages. It is not a legal conclusion, WCAG certification, or a promise of compliance.
