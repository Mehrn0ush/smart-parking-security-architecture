# Release Notes v1.0

This release marks the repository as a stable, architecture-first reference model for connecting Structurizr/C4 architecture with CycloneDX-oriented governance outputs.

## What v1.0 Stabilizes

- the layered architecture, policy, evidence, and generated-output model
- the rule that [`../model/workspace.dsl`](../model/workspace.dsl) remains the source of truth
- the small set of stable governance terms used across policy, evidence, and generated outputs
- the static reporting surface under [`../bom/`](../bom/)

## What This Repository Demonstrates

- how architecture scope can drive SBOM, CBOM, VEX, and provenance thinking
- how evidence binding, review, approval, waiver, and escalation semantics can be modeled without polluting the DSL
- how static generated summaries can make governance posture understandable for students and practitioners

## What This Repository Does Not Claim

- real scanner-complete package inventories
- supplier-issued VEX artifacts
- signed or cryptographically verified provenance unless a local file really supports that claim
- discovered crypto inventories for the modeled trust boundaries

## Release-Hardening Highlights

- terminology is now aligned around `evidence_support_state`, `approval_presence_state`, `approval_state`, and `governed_maturity_state`
- reviewer actions are now visible both by reviewer group and by artifact type
- trust-boundary-focused posture is now summarized statically
- schema and output contracts are documented in [`schema-contracts.md`](schema-contracts.md)

## Known Nuance

Structurizr export remains semantically stable but not byte-stable.

That means:

- `workspace.json` semantic verification is the real integrity check
- byte-for-byte differences alone are not treated as architectural drift
