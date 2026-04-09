# Schema And Output Contracts

This repository is architecture-first, but it also exposes a small set of stable policy, evidence, and generated-output concepts for a `v1.0.0`-style release.

## Stable Source-Of-Truth Rule

The stable authoring rule is:

- [`../model/workspace.dsl`](../model/workspace.dsl) is the architecture source of truth
- [`../model/workspace.json`](../model/workspace.json) is a generated convenience artifact
- policy and evidence stay outside the DSL

This contract should not change without a deliberate major-version discussion.

## Stable Policy Concepts

The following policy concepts are treated as stable repository vocabulary:

- subject identity anchored by `arch_ref`, `bom_ref`, and `runtime_unit`
- artifact kinds: `sbom`, `cbom`, `vex`, `provenance`
- review roles: `reviewer_group`, `approval_group`, `escalation_group`
- approval semantics: `approval_required_for_evidence_backed`, `approval_validity_days`, `approval_expiring_soon_days`
- dual-review semantics: `dual_review_required`, `secondary_approval_group`

Future additions can extend these concepts, but should not rename them lightly.

## Stable Evidence Concepts

The following evidence concepts are treated as stable:

- evidence subject decomposition through `evidence_subject_id`
- evidence adapters such as `cyclonedx_json`, `advisory_record`, and `attestation_reference`
- artifact-specific review metadata
- approval signoff records
- provenance assurance terms such as `reference_only`
- waiver terms such as `waiver_state`, `waiver_owner`, and `waiver_expiry`

## Stable Generated Output Concepts

The following generated-output concepts are treated as stable and are safe to reference in documentation or teaching material:

- `derived_maturity_state`
- `governed_maturity_state`
- `freshness_state`
- `evidence_support_state`
- `approval_presence_state`
- `approval_state`
- `review_blocking`
- `escalation_required`

These concepts appear in:

- [`../bom/manifest.json`](../bom/manifest.json)
- [`../bom/evidence-matrix.md`](../bom/evidence-matrix.md)
- [`../bom/evidence-matrix.csv`](../bom/evidence-matrix.csv)
- [`../bom/governance-summary.md`](../bom/governance-summary.md)
- [`../bom/reviewer-actions.md`](../bom/reviewer-actions.md)
- [`../bom/artifact-type-actions.md`](../bom/artifact-type-actions.md)
- [`../bom/waiver-summary.md`](../bom/waiver-summary.md)
- [`../bom/attention-now.md`](../bom/attention-now.md)
- [`../bom/trust-boundary-summary.md`](../bom/trust-boundary-summary.md)

## Additive vs Breaking Changes

For this repository:

- additive changes:
  - new optional policy fields
  - new optional evidence fields
  - new generated summary sections
  - new static output files
- breaking changes:
  - renaming stable field names
  - removing current stable output files
  - changing the meaning of `derived_maturity_state`, `governed_maturity_state`, `evidence_support_state`, `approval_presence_state`, or `approval_state`
  - moving policy or evidence semantics into the DSL

## What Is Intentionally Not A Stable Contract

The following are intentionally flexible:

- exact example counts in generated summaries
- which six tracked subjects are in scope for the current learning milestone
- example evidence file contents
- the wording of explanatory prose in the docs

Those details may evolve without changing the core repository model.
