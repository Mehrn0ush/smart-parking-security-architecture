# Evidence Bindings Model

Milestone 3 added an explicit evidence layer.

Milestone 4 added two small but important ideas on top of that layer:

- derived maturity transitions
- freshness and staleness evaluation

Milestone 5 adds two more:

- evidence subject decomposition
- evidence admissibility and precedence

Milestone 6 adds two more:

- lightweight evidence adapters
- owner and review workflow fields

Milestone 7 adds two more:

- artifact-specific review state
- stale-evidence escalation and handoff

The repository now has four layers:

1. architecture in [`../../model/workspace.dsl`](../../model/workspace.dsl)
2. policy in [`../../model/supply-chain-mapping.yaml`](../../model/supply-chain-mapping.yaml)
3. evidence bindings in [`../../model/supply-chain-evidence.yaml`](../../model/supply-chain-evidence.yaml)
4. generated artifacts in [`../../bom/`](../../bom/)

## Why Evidence Is Separate From Policy

Policy says what should exist and what kind of subject it is.

Evidence says where proof would come from and how trustworthy that proof is.

Those are different concerns:

- architecture changes with system design
- policy changes with governance decisions
- evidence changes with pipelines, scanner outputs, advisory review, and manual verification

Keeping evidence separate makes the repository easier to teach, maintain, and extend.

## Evidence Schema

The evidence file is small on purpose.

Each subject is linked by:

- `arch_ref`
- `bom_ref`
- `runtime_unit`

Each architecture subject can now define one or more `evidence_subjects`.

This is the difference:

- the architecture subject comes from the Structurizr container
- the evidence subject is a narrower runtime, package, control-profile, or managed-service view that evidence can attach to

Each evidence subject can define evidence for:

- `sbom`
- `cbom`
- `vex`
- `provenance`

Each artifact evidence block can include:

- `content_status`
- `binding_state`
- `evidence_scope`
- `review`
- `sources`

Each source can include:

- `evidence_kind`
- `adapter`
- `source_type`
- `collection_method`
- `reference`
- `maturity`
- `confidence`
- `last_verified`
- `limitations`

Each evidence subject can also include:

- `review_status`
- `last_reviewed`
- `reviewed_by`

Artifact review now takes precedence over subject-level review when it exists.

That matters because one evidence subject can have different review posture per artifact type:

- SBOM may be reviewed and current
- CBOM may still be under control-only review
- VEX may require separate advisory review
- provenance may be present but stale

### Evidence Subject Example

`Gateway Service` now decomposes into:

- `gateway-runtime`
- `gateway-control-profile`

That lets the repository say:

- runtime-oriented SBOM evidence belongs to the runtime subject
- control and crypto-boundary evidence can belong to a separate control-profile subject

`Edge AI Runtime` also demonstrates a second pattern:

- `edge-ai-runtime-service`
- `edge-ai-model-package`

That keeps AI runtime concerns and model-package concerns distinct without changing the architecture model.

## Transition States

The generator now derives a maturity state for each artifact kind:

- `scaffolded`
- `partially_evidenced`
- `evidence_backed`
- `not_applicable`

These states are computed from policy rules plus evidence bindings.

### Simple Transition Logic

- `scaffolded`: no qualifying evidence source yet, or only planned bindings
- `partially_evidenced`: at least one qualifying source exists and the binding is `linked` or `verified`
- `evidence_backed`: a stronger rule is met, typically requiring `verified`, at least one qualifying source, non-placeholder references, and `last_verified`

This repository is intentionally conservative. A placeholder reference can support planning, but it does not count as evidence-backed.

## Evidence Kinds

Artifact type and evidence kind are not the same.

- artifact type says what is being generated: `sbom`, `cbom`, `vex`, `provenance`
- evidence kind says what sort of proof is attached to that artifact

Current evidence kinds include:

- `scanner_output`
- `package_manifest`
- `image_descriptor`
- `deployment_manifest`
- `crypto_policy`
- `advisory_record`
- `attestation`
- `repo_control_document`

This is important because not every evidence kind can support every transition.

Examples:

- a `repo_control_document` can support partial CBOM reasoning
- a `crypto_policy` can outrank a generic control document for CBOM selection
- an `advisory_record` is required before VEX can move upward
- a placeholder scanner reference still does not make an SBOM evidence-backed

## Freshness States

The generator also derives a freshness state:

- `fresh`
- `stale`
- `expired`
- `unknown`
- `not_applicable`

Freshness is calculated against the configured evaluation date in [`../../model/supply-chain-evidence.yaml`](../../model/supply-chain-evidence.yaml).

The current evaluation reference is stored there so generation remains deterministic.

## Artifact-Specific Review

Milestone 7 moves the main review state down to the artifact level.

Typical fields are:

- `review_status`
- `last_reviewed`
- `reviewed_by`
- `review_notes`
- `next_review_due`

This keeps review semantics aligned with the thing being trusted.

## Escalation And Handoff

Freshness by itself is not enough.

Milestone 7 adds lightweight governance semantics on top of freshness:

- `escalation_required`
- `escalation_status`
- `handoff_to`
- `review_blocking`
- `governed_maturity_state`

This lets the repository distinguish:

- an artifact that is still fresh and trusted
- an artifact that is stale or expired and needs owner action
- an artifact whose evidence-backed status would be blocked by expired evidence under the current policy

## Where The Rules Live

The transition and freshness rules are governed in [`../../model/supply-chain-mapping.yaml`](../../model/supply-chain-mapping.yaml).

That is intentional:

- evidence files carry facts and bindings
- policy files carry decision logic

This keeps the evidence file readable and avoids mixing facts with governance rules.

The policy file also now carries:

- admissible evidence kinds per artifact type
- precedence order for competing evidence sources

## Current Meaning Of The Main Fields

### `content_status`

Describes what the generated repository content currently is.

Typical values:

- `scaffolded`
- `not-collected`
- `not-applicable`
- later: `partially-evidenced`
- later: `evidence-backed`

### `binding_state`

Describes whether the repository has a meaningful evidence attachment point.

Typical values:

- `planned`
- `linked`
- `verified`
- `not-applicable`

### `collection_method`

Describes the expected provenance of the future evidence source.

Typical values:

- `scanner_derived`
- `imported`
- `manually_curated`
- `advisory_reviewed`

### `evidence_kind`

Describes what kind of proof a source represents.

Typical values:

- `scanner_output`
- `package_manifest`
- `crypto_policy`
- `advisory_record`
- `attestation`
- `repo_control_document`

### `precedence_outcome`

Describes how a source was used after admissibility and precedence were applied.

Typical values:

- `selected`
- `supporting`
- `none`

## How To Read The Generated Outputs

If a BOM file says:

- `artifact_status = scaffolded`
- `content_status = scaffolded`
- `evidence_binding_state = planned`
- `derived_maturity_state = scaffolded`

that means:

- the repository intentionally generated a synthetic scaffold
- there is a defined place where real evidence should attach later
- there is still no committed scanner/advisory/manual evidence artifact

If a BOM file says:

- `derived_maturity_state = partially_evidenced`
- `freshness_state = fresh`

that means:

- the repository has at least one qualifying linked or verified evidence source
- the evidence is recent enough under the current freshness rule
- the repository still does not claim full evidence-backed coverage unless the stricter rule is met

## Evidence Matrix

Milestone 3 generates:

- [`../../bom/evidence-matrix.md`](../../bom/evidence-matrix.md)
- [`../../bom/evidence-matrix.csv`](../../bom/evidence-matrix.csv)

These files summarize:

- which architecture subject is being tracked
- which evidence subject supplied the current row
- which artifact kind is in scope
- what the current policy status is
- whether the content is scaffolded or evidence-backed
- what the derived maturity state is
- whether the evidence is fresh, stale, expired, or unknown
- what evidence kind and source type are present
- which source won precedence
- what the current maturity/confidence looks like

## Current Limitations

This evidence layer is still intentionally conservative.

It does not:

- commit real scanner outputs
- commit real provenance attestations
- commit real advisory verdicts
- claim evidence-backed VEX statements

At the moment, the strongest example is intentionally modest:

- the Gateway Service CBOM becomes `partially_evidenced`
- it does so from local design/control artifacts already present in the repository
- it still does not claim an evidence-backed crypto inventory

Milestone 5 extends that example by showing:

- one architecture subject can have multiple evidence subjects
- multiple evidence kinds can exist for one artifact type
- precedence selects the current best admissible source without discarding the supporting sources

Milestone 6 extends it again by showing:

- a selected source can be a real local file normalized by an adapter
- review ownership can be shown alongside the evidence subject
- evidence-backed and partially-evidenced states can now be demonstrated with real local inputs instead of only placeholders

Milestone 7 adds one more teaching example:

- `edge-ai-model-package` provenance uses a real local provenance-reference record
- it is normalized with `attestation_reference`
- it becomes `partially_evidenced`
- its freshness is `expired`
- that expired state triggers escalation to the AI assurance board

This does not claim a signed attestation. It demonstrates governance around an incomplete AI provenance trail.

Milestone 8 extends the same model in three practical ways:

- review responsibility is now artifact-specific at team level, not only subject-level
- provenance can now be marked as `reference_only` or as a stronger signed or verified form later
- repository summaries now count overdue review, review-blocking posture, and escalation-required artifacts

Current milestone 8 examples:

- Gateway Service SBOM stays raw `evidence_backed`, but becomes governed `partially_evidenced` because review is overdue
- `edge-ai-model-package` provenance is explicitly `reference_only`, so students can see the difference between provenance intent and signed attestation proof
- Secrets Manager VEX is now a trust-boundary example of stale reviewed evidence that escalates without pretending to be a supplier-issued VEX artifact

Milestone 9 extends the evidence model again:

- review is now lifecycle-aware, not only status-aware
- approval can be required for governed `evidence_backed` outcomes
- waivers can suppress escalation or similar workflow effects without changing what the evidence actually proves
- provenance now has an explicit assurance ladder

Current milestone 9 examples:

- Gateway Service SBOM uses lifecycle `in_review` plus approval-required governance, so it stays raw `evidence_backed` but governed `partially_evidenced`
- Identity Provider CBOM uses an active waiver to suppress escalation while the managed crypto boundary remains under supplier control
- `edge-ai-model-package` provenance remains `reference_only`, which is intentionally weaker than `attestation_present`, `signature_verified`, or `policy_verified`

Milestone 10 adds one more set of derived interpretations:

- approval can be `current`, `expiring_soon`, `expired`, or `not_applicable`
- dual review can be required and still unsatisfied even when one approval already exists
- waivers can be active and also expiring soon

Milestone 12 tightens the output semantics:

- `evidence_support_state` now tells readers whether the current artifact posture is still only planned, merely linked, or backed by a verified local source
- `approval_presence_state` now tells readers whether an approval actually exists, separately from whether that approval is still current
- the static `attention-now.md` view highlights approval-expired items, low-assurance AI provenance, waiver-expiry pressure, and stale trust-boundary evidence without pretending to be a live dashboard

Current milestone 10 examples:

- Gateway Service SBOM has an expired approval
- Gateway Service CBOM and `edge-ai-model-package` provenance both show dual-review pending
- Identity Provider CBOM has a waiver that is active today but expiring soon

It creates the structure needed for that later work without pretending the evidence already exists.
