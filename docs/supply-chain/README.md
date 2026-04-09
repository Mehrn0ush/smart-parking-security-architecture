# Structurizr And CycloneDX

Structurizr and CycloneDX describe different layers of the same system.

- Structurizr/C4 explains structure, responsibilities, trust boundaries, deployment zones, and relationships.
- CycloneDX explains composition, cryptographic scope, and vulnerability-exploitability assertions for specific products or deployable units.

This repository keeps those roles separate on purpose.

## Why They Are Related But Not The Same

The Structurizr model answers questions such as:

- which containers are internet-facing?
- which services are high risk?
- where are the edge, fog, and cloud boundaries?
- which units handle identity, secrets, or AI models?

CycloneDX answers different questions:

- what software product or runtime unit does an SBOM refer to?
- which architecture elements need a CBOM because they terminate TLS, issue tokens, or manage trust material?
- which deployable unit should a VEX statement attach to?

The architecture decides **where supply-chain evidence should attach**. The BOMs then carry the downstream evidence.

## Why Milestone 2 Exists

The first milestone proved that selected architecture containers could drive repeatable SBOM, CBOM, and VEX scaffolds.

Milestone 2 exists because some supply-chain policy was still too implicit.

This repository now separates:

- architecture anchors in [`../../model/workspace.dsl`](../../model/workspace.dsl)
- generated model data in [`../../model/workspace.json`](../../model/workspace.json)
- supply-chain policy in [`../../model/supply-chain-mapping.yaml`](../../model/supply-chain-mapping.yaml)
- derived artifacts in [`../../bom/`](../../bom/)

This keeps the DSL lightweight while making supplier type, artifact maturity, exploitability context, and cyber-physical semantics explicit.

## Why Milestone 3 Exists

Milestone 2 made policy explicit, but it still did not say where real evidence should come from.

Milestone 3 adds an evidence layer:

- [`../../model/supply-chain-evidence.yaml`](../../model/supply-chain-evidence.yaml)

This layer does not fabricate evidence.

Instead, it records:

- which future source should support SBOM, CBOM, VEX, or provenance
- whether the current content is still scaffolded
- how mature or trustworthy a future evidence source is expected to be
- when a source was last verified, or whether it has not yet been verified

## Why Milestone 4 Exists

Evidence bindings alone are not enough.

Teams also need to know:

- whether a binding is strong enough to change the current artifact state
- whether the evidence is fresh enough to trust for current decisions

Milestone 4 adds small, explicit state logic so the repository can distinguish:

- a scaffold with only planned evidence
- a subject with partial supporting evidence
- a subject that could later become evidence-backed under stricter rules

## Why Milestone 5 Exists

Milestone 4 still treated each tracked architecture subject too much like a single evidence bucket.

That is too limiting for real systems.

Milestone 5 adds:

- evidence subject decomposition
- evidence kind semantics
- admissibility rules
- precedence rules

This matters because one architecture subject can legitimately have:

- a runtime service view
- a model-package view
- a control-profile view
- multiple evidence sources with different strengths

The repository now makes those distinctions explicit without changing the Structurizr model.

## Why Milestone 6 Exists

Milestone 5 could describe evidence well, but it still treated evidence mostly as declared metadata.

Milestone 6 adds two small operational ideas:

- lightweight evidence adapters for a few real local input shapes
- lightweight ownership and review workflow semantics

This moves the repository from "we know where evidence should attach" to "we can ingest a small amount of real local evidence and show who reviews it."

## Current Practical Scope

This package starts with six high-value containers:

- Gateway Service
- Edge AI Runtime
- API Gateway
- Event Bus
- Identity Provider
- Secrets Manager

This is a good starting point because those containers cover:

- edge cyber-physical control
- AI inference and model integrity
- internet-facing API boundaries
- event-driven backbone services
- identity and trust services
- secret and key-management surfaces

## What Students Should Understand

Students should not treat SBOM, CBOM, and VEX as generic files detached from architecture.

They should learn that:

- SBOM scope comes from a deployable or runtime unit
- architecture identity and runtime identity are related but not the same
- CBOM scope comes from cryptographic responsibility, not from every service by default
- VEX scope comes from a product or deployable unit that may be vulnerable, not from the entire architecture diagram
- external software systems can stay in the architecture model without being flattened into local package inventories
- an evidence binding is not the same thing as evidence-backed content
- freshness matters; old evidence should not be read the same way as recent evidence

## What Engineers Should Understand

Engineers should use the architecture model to decide:

- which containers need scanner-backed SBOM generation later
- where crypto discovery or certificate inventory belongs
- where vulnerability assertions should be maintained
- which deployable units are important enough to track first
- which policy attributes belong outside the DSL because they change faster than architecture structure
- which evidence sources are planned versus actually committed
- how maturity transitions are computed from simple rules rather than opinion

## What Security Architects Should Understand

Security architects should use the mapping to connect:

- trust boundaries
- high-risk containers
- cryptographic control points
- AI/ML integrity surfaces
- exploitability decisions
- physical control influence and safety impact
- evidence maturity and its limits
- evidence freshness and staleness

without turning the DSL into an unreadable dependency graph.

## Current Limitations

This repository intentionally avoids pretending that it already contains real package or image scan results.

Current limitations:

- SBOM files are scaffolds, not scanner-derived dependency inventories
- CBOM files capture cryptographic scope and expected controls, not validated key material
- VEX files are empty scaffolds until scanner/advisory data is available
- the mapping file is policy, not evidence
- the evidence file currently contains bindings and placeholders, not collected evidence artifacts
- only selected containers are in scope for the current milestone

Current milestone 6 result:

- Gateway Service CBOM is the main partial-evidence example
- it uses local repository files as control evidence
- it is still not treated as a full discovered crypto inventory
- Gateway Service also shows that a single architecture subject can map to multiple evidence subjects
- Edge AI Runtime shows that runtime and model-package evidence can be separated
- Gateway Service SBOM now has a small evidence-backed pilot using a real local CycloneDX input file
- API Gateway VEX now has a partial-evidence pilot using a real local advisory-review record

## Why Milestone 7 Exists

Milestone 6 added real local inputs, but review was still too coarse.

Milestone 7 adds:

- artifact-specific review state
- stale-evidence escalation and handoff
- an AI provenance-oriented example

This matters because a single evidence subject can have different trust posture by artifact type, and freshness without handoff is not enough for governance.

Current milestone 7 result:

- Gateway Service SBOM remains the main evidence-backed pilot
- API Gateway VEX remains the main advisory-reviewed partial-evidence pilot
- Edge AI model-package provenance now demonstrates stale AI provenance with explicit escalation to the AI assurance board

## Why Milestone 8 Exists

Milestone 7 proved that stale evidence could escalate, but it still treated reviewer responsibility too coarsely.

Milestone 8 adds:

- reviewer groups that vary by artifact type
- explicit provenance distinction between reference-only and signed or verified attestation-backed inputs
- a static governance summary so readers can see overdue review, escalation, and review-blocking counts without reading every artifact file
- an explicit review-blocking downgrade example
- a secrets-focused escalation example

Current milestone 8 result:

- Gateway Service SBOM is still raw `evidence_backed`, but its governed state is downgraded to `partially_evidenced` because review is overdue
- Edge AI model-package provenance remains reference-only and therefore does not overclaim signed provenance
- Secrets Manager VEX now shows a stale local advisory-review binding that escalates to trust governance
- [`../../bom/governance-summary.md`](../../bom/governance-summary.md) summarizes the current repository-wide governance posture

## Why Milestone 9 Exists

Milestone 8 made governance visible, but it still treated review as mostly point-in-time state.

Milestone 9 adds:

- a small review lifecycle model
- approval-aware reviewer-group semantics
- a provenance assurance ladder
- waiver and exception handling
- action-oriented governance summaries for overdue, blocked, awaiting-approval, and waived artifacts

Current milestone 9 result:

- Gateway Service SBOM is now the main approval-lifecycle example: raw `evidence_backed`, governed `partially_evidenced`, lifecycle `in_review`, and awaiting approval
- Identity Provider CBOM is the waiver example: it remains scaffolded, but an active waiver suppresses escalation while the managed crypto boundary stays opaque
- Edge AI model-package provenance now uses the explicit assurance ladder and remains `reference_only`
- Secrets Manager VEX remains the main secrets-focused escalation example

## Why Milestone 10 Exists

Milestone 9 introduced approval and waiver semantics, but it still treated them mostly as present-or-absent conditions.

Milestone 10 adds:

- approval expiry
- dual-review rules for selected high-risk artifacts
- waiver-expiry inventory
- reviewer-group action summaries

Current milestone 10 result:

- Gateway Service SBOM is the main approval-expiry example: evidence still exists, but approval is expired and the governed state stays degraded
- Gateway Service CBOM and Edge AI provenance are the main dual-review examples
- Identity Provider CBOM is the main expiring-waiver example
- [`../../bom/reviewer-actions.md`](../../bom/reviewer-actions.md) now groups action items by reviewer group

## Why Milestone 11 Exists

Milestone 10 made approval expiry and dual review explicit, but it still needed more operational clarity for criticality, action separation, and waiver ownership.

Milestone 11 adds:

- criticality-aware approval validity windows
- separated reviewer actions such as `approval_expired`, `review_overdue`, and `dual_review_pending`
- waiver summaries grouped by waiver owner
- explicit secondary signoff visibility

## Why Milestone 12 Exists

Milestone 11 made governance more operational, but some assurance semantics were still easy to conflate.

Milestone 12 adds:

- `evidence_support_state` to show whether the current artifact posture is still only planned, merely linked, or backed by a verified local source
- `approval_presence_state` to separate "approval exists" from "approval is still current"
- artifact-type-aware summary counts in [`../../bom/governance-summary.md`](../../bom/governance-summary.md)
- a concise static attention view in [`../../bom/attention-now.md`](../../bom/attention-now.md)

Current milestone 12 result:

- Gateway Service SBOM remains the clearest "evidence exists but approval is stale" example
- Gateway Service CBOM shows that dual review can be satisfied while approval still moves toward expiry
- Edge AI model-package provenance still honestly remains `reference_only`, and the new attention view calls it out as low-assurance AI provenance
- Secrets Manager VEX now appears both as an escalation item and as a stale trust-boundary artifact in the static attention summary

## Next Evolution Path

The next steps would be:

1. attach scanner outputs to the same `bom.ref` values
2. add image/package provenance for deployable units
3. enrich CBOM generation with certificate and algorithm discovery
4. add VEX assertions from real vulnerability analysis
5. extend tracking to more containers once the conventions are stable

## v1.0 Contract Notes

For the release-hardened repository, the following are treated as stable teaching and automation terms:

- `derived_maturity_state`
- `governed_maturity_state`
- `freshness_state`
- `evidence_support_state`
- `approval_presence_state`
- `approval_state`
- `reference_only`

See:

- [`../schema-contracts.md`](../schema-contracts.md)
- [`../release-notes-v1.md`](../release-notes-v1.md)
