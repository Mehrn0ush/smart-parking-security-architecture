# CycloneDX Artifacts

This directory contains architecture-aware CycloneDX artifacts derived from the Structurizr model.

Important rule:

- [`../model/workspace.dsl`](../model/workspace.dsl) remains the architecture source of truth.
- The JSON files in this directory are generated convenience artifacts.

## What Is Here

- [`manifest.json`](manifest.json): generated index of tracked containers and their BOM scopes
- [`coverage-matrix.md`](coverage-matrix.md): generated human-readable coverage summary
- [`coverage-matrix.csv`](coverage-matrix.csv): generated machine-readable coverage summary
- [`evidence-matrix.md`](evidence-matrix.md): generated human-readable evidence summary
- [`evidence-matrix.csv`](evidence-matrix.csv): generated machine-readable evidence summary
- [`sbom/`](sbom): CycloneDX SBOM scaffolds for selected deployable units
- [`cbom/`](cbom): CycloneDX CBOM scaffolds only for crypto-relevant containers
- [`vex/`](vex): CycloneDX VEX scaffolds for the same architecture-tracked units

## What These Files Are

These files are **not** package-manager scans and **not** container image inventories.

They are:

- generated from [`../model/workspace.json`](../model/workspace.json)
- guided by lightweight metadata on selected Structurizr containers
- refined by policy in [`../model/supply-chain-mapping.yaml`](../model/supply-chain-mapping.yaml)
- annotated by evidence bindings in [`../model/supply-chain-evidence.yaml`](../model/supply-chain-evidence.yaml)
- intended to teach how architecture scope can drive supply-chain artifacts

They now also include derived status logic:

- maturity state such as `scaffolded` or `partially_evidenced`
- freshness state such as `fresh`, `stale`, `expired`, or `unknown`
- evidence subject decomposition for selected subjects
- admissibility and precedence over competing evidence kinds
- owner and review cadence
- adapter and input-state metadata for selected real local evidence files

## What These Files Are Not

They are not:

- a replacement for software composition analysis
- a complete vulnerability truth source
- a live certificate or key inventory

Production teams should replace or enrich these scaffolds with scanner-backed SBOMs, cryptographic discovery, and vulnerability analysis outputs.

## How To Regenerate

From the repository root:

```bash
python3 tools/generate_cyclonedx_artifacts.py
python3 tools/generate_cyclonedx_artifacts.py --check
```

## Why Some Containers Have CBOM And Others Do Not

Not every container needs a CBOM.

This repository attaches CBOM scaffolds only to containers where the architecture strongly suggests cryptographic boundaries or trust-material handling, such as:

- gateway and edge transport boundaries
- API termination and token validation
- identity and token services
- secrets and key-management services
- AI runtime integrity and model-delivery paths

## How To Read Maturity Honestly

`partially_evidenced` does not mean “production-proven”.

It means the repository has enough non-empty, qualifying evidence bindings to move beyond a pure scaffold under the current rules.

In this repository, the best current example is the Gateway Service CBOM, which uses local control artifacts already present in the repository. It is still not treated as a discovered crypto inventory.

Milestone 5 adds one more teaching point:

- one architecture subject can map to multiple evidence subjects
- one artifact type can have more than one evidence source
- the generated evidence matrix shows which source was selected and which remained supporting

Milestone 6 adds a limited real-input pilot:

- Gateway Service SBOM uses a real local CycloneDX JSON file
- API Gateway VEX uses a real local advisory-review record

These inputs are still intentionally modest. They demonstrate ingestion and reviewability, not production-grade completeness.

Milestone 7 adds one more teaching point:

- review state is now artifact-specific
- stale or expired evidence can trigger escalation and handoff
- the edge AI model-package provenance example shows how incomplete AI provenance should still be governed explicitly

Milestone 8 adds static governance visibility:

- [`governance-summary.md`](governance-summary.md) gives repository-level counts for governed maturity, freshness, overdue review, review blocking, and escalation
- reviewer groups are now shown per artifact type so SBOM, CBOM, VEX, and provenance do not all imply the same review path
- Gateway Service SBOM is the main review-blocking downgrade example
- Secrets Manager VEX is the main trust-boundary escalation example outside the AI path

Milestone 9 adds workflow-oriented reading guidance:

- `governance-summary.md` now also counts awaiting-approval and waived artifacts
- the evidence matrix now shows review lifecycle, approval group, waiver state, and provenance assurance level
- Gateway Service SBOM is the main approval-lifecycle example
- Identity Provider CBOM is the main waiver example

Milestone 10 adds two more static outputs and interpretations:

- `governance-summary.md` now counts approval expiry, dual-review pending items, and waivers expiring soon
- [`reviewer-actions.md`](reviewer-actions.md) groups action items by reviewer group
- Gateway Service SBOM is the main approval-expiry example
- Gateway Service CBOM and Edge AI provenance are the main dual-review examples
