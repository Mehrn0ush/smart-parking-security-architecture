# Evidence Adapters

Milestone 6 adds a small normalization layer on top of the existing evidence model.

The goal is practical:

- accept a few real input shapes
- normalize them into the repository's evidence model
- keep the architecture model unchanged
- keep the repository honest about what is truly evidence-backed

## Supported Input Shapes

The generator currently supports these adapters:

- `cyclonedx_json`
- `package_manifest`
- `advisory_record`
- `attestation_reference`

The adapter is declared on the evidence source in [`../../model/supply-chain-evidence.yaml`](../../model/supply-chain-evidence.yaml).

## What Normalization Does

Normalization adds a small, stable summary for local input files, such as:

- adapter type
- input state
- source digest
- key identifying fields from the input

Examples:

- a CycloneDX JSON file yields component name, version, component count, and spec version
- an advisory review record yields subject, review outcome, review status, and reviewed date

## Current Pilot Inputs

The repository currently uses two real local inputs:

- [`../../evidence/imports/gateway-runtime-imported-sbom.cdx.json`](../../evidence/imports/gateway-runtime-imported-sbom.cdx.json)
- [`../../evidence/reviews/api-gateway-vendor-advisory-review.json`](../../evidence/reviews/api-gateway-vendor-advisory-review.json)
- [`../../evidence/references/edge-ai-model-package-provenance-reference.json`](../../evidence/references/edge-ai-model-package-provenance-reference.json)

These are intentionally modest:

- the gateway SBOM input is a real CycloneDX file, but not a discovered dependency inventory
- the API Gateway advisory input is a real local review record, but not a supplier-issued VEX artifact
- the edge AI provenance input is a real local provenance-reference record, but not a signed attestation

## Reviewability

Milestone 6 also adds lightweight review semantics:

- `owner`
- `review_cadence`
- `review_status`
- `last_reviewed`
- `reviewed_by`

These fields help readers answer:

- who owns the evidence attachment
- how often it should be revisited
- whether the current input has actually been reviewed

Milestone 7 refines that further by making review state artifact-specific and by deriving escalation when freshness is no longer acceptable.

## Current Limitations

The adapters are intentionally small.

They do not yet:

- fetch remote artifacts
- verify digital signatures
- validate advisory feeds against external services
- infer package completeness
- infer exploitability conclusions from prose alone

They simply normalize a few local input shapes in a deterministic and teachable way.
