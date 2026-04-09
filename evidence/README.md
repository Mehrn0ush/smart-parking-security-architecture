# Evidence Inputs

This directory contains small, honest evidence input files used by the repository's milestone 6, milestone 7, milestone 8, milestone 9, and milestone 10 adapters.

These files are intentionally limited:

- they demonstrate real input shapes
- they do not pretend to be full scanner exports, vendor advisories, or signed attestations unless they truly are
- they participate in workflow, waiver, freshness, and assurance examples, but they do not prove more than their local file content supports

Current pilot inputs:

- [`imports/gateway-runtime-imported-sbom.cdx.json`](imports/gateway-runtime-imported-sbom.cdx.json): a real CycloneDX JSON file used to exercise imported SBOM normalization
- [`reviews/api-gateway-vendor-advisory-review.json`](reviews/api-gateway-vendor-advisory-review.json): a real local advisory-review record used to exercise VEX review normalization
- [`references/edge-ai-model-package-provenance-reference.json`](references/edge-ai-model-package-provenance-reference.json): a real local provenance-reference record used to exercise AI provenance review, freshness, and escalation logic
- [`reviews/secrets-manager-vault-advisory-review.json`](reviews/secrets-manager-vault-advisory-review.json): a real local trust-review record used to exercise stale secrets-platform VEX governance without claiming a supplier-issued VEX file
