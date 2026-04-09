# Evidence Inputs

This directory contains small, honest evidence input files used by the repository's milestone 6 and milestone 7 adapters.

These files are intentionally limited:

- they demonstrate real input shapes
- they do not pretend to be full scanner exports, vendor advisories, or signed attestations unless they truly are

Current pilot inputs:

- [`imports/gateway-runtime-imported-sbom.cdx.json`](imports/gateway-runtime-imported-sbom.cdx.json): a real CycloneDX JSON file used to exercise imported SBOM normalization
- [`reviews/api-gateway-vendor-advisory-review.json`](reviews/api-gateway-vendor-advisory-review.json): a real local advisory-review record used to exercise VEX review normalization
- [`references/edge-ai-model-package-provenance-reference.json`](references/edge-ai-model-package-provenance-reference.json): a real local provenance-reference record used to exercise AI provenance review, freshness, and escalation logic
