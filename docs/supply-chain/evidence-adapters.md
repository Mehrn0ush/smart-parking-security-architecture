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

The repository currently uses a small set of real local inputs:

- [`../../evidence/imports/gateway-runtime-imported-sbom.cdx.json`](../../evidence/imports/gateway-runtime-imported-sbom.cdx.json)
- [`../../evidence/reviews/api-gateway-vendor-advisory-review.json`](../../evidence/reviews/api-gateway-vendor-advisory-review.json)
- [`../../evidence/references/edge-ai-model-package-provenance-reference.json`](../../evidence/references/edge-ai-model-package-provenance-reference.json)
- [`../../evidence/reviews/secrets-manager-vault-advisory-review.json`](../../evidence/reviews/secrets-manager-vault-advisory-review.json)

These are intentionally modest:

- the gateway SBOM input is a real CycloneDX file, but not a discovered dependency inventory
- the API Gateway advisory input is a real local review record, but not a supplier-issued VEX artifact
- the edge AI provenance input is a real local provenance-reference record, but not a signed attestation
- the secrets-manager advisory input is a real local trust review record, but not a supplier-issued VEX artifact

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

Milestone 8 adds two more adapter-facing semantics:

- attestation-related inputs now distinguish `reference_only` provenance from stronger signed or verified provenance
- generated outputs now surface reviewer group, escalation group, overdue review, and review-blocking posture alongside the normalized input

Milestone 9 keeps the adapters lightweight, but gives their outputs more workflow meaning:

- review lifecycle is now explicit, so a normalized input can be pending, in review, approved, rejected, waived, or superseded
- approval-aware governance can keep a raw `evidence_backed` artifact out of governed `evidence_backed` state until approval is refreshed
- attestation-related inputs now also expose a provenance assurance level such as `reference_only` or, later, `attestation_present`

Milestone 10 keeps the adapters static, but makes their outputs more time-aware:

- imported inputs can now carry approval signoff metadata used to derive approval expiry
- selected artifacts can require a second approval group even when only one local signoff exists
- local inputs can therefore drive reviewer action summaries without becoming a workflow engine

## Current Limitations

The adapters are intentionally small.

They do not yet:

- fetch remote artifacts
- verify digital signatures
- validate advisory feeds against external services
- infer package completeness
- infer exploitability conclusions from prose alone

They simply normalize a few local input shapes in a deterministic and teachable way.
