# Architecture-To-CycloneDX Mapping Specification

This document defines the practical mapping used in this repository.

## Integration Points

The repository uses six integration points:

1. Architecture metadata in [`../../model/workspace.dsl`](../../model/workspace.dsl)
2. Generated model export in [`../../model/workspace.json`](../../model/workspace.json)
3. Supply-chain policy in [`../../model/supply-chain-mapping.yaml`](../../model/supply-chain-mapping.yaml)
4. Evidence bindings in [`../../model/supply-chain-evidence.yaml`](../../model/supply-chain-evidence.yaml)
5. Generated CycloneDX scaffolds and coverage/evidence reports in [`../../bom/`](../../bom/)
6. Verification workflow in [`../../tools/generate_cyclonedx_artifacts.py`](../../tools/generate_cyclonedx_artifacts.py)

Reasoning:

- the DSL stays small and authoritative
- the JSON is a machine-friendly bridge for tooling
- the policy file makes artifact applicability and maturity explicit without bloating the DSL
- the evidence file shows where proof would come from without pretending it already exists
- the BOM directory is the natural place for derived supply-chain outputs
- the script makes the mapping repeatable and testable

## Mapping Model

| Structurizr concept | CycloneDX concept | Repository treatment |
| --- | --- | --- |
| Software system | product family / architecture context | kept in DSL and docs; not directly emitted as BOM files in milestone 1 |
| Container | primary architecture attachment point | selected containers are linked to policy subjects that generate SBOM and VEX; crypto-relevant containers also generate CBOM |
| Component | optional internal implementation clue | not emitted as dependency inventory; only used as heuristic evidence for CBOM scope |
| Deployable unit / runtime unit | BOM subject | represented by `runtime.unit` and policy subject metadata |
| Trust boundary / deployment zone | supply-chain context | encoded as `deployment.zone` property and copied into generated BOM properties |
| External software system | provider / external dependency context | remains in architecture model; referenced as context, not flattened into local dependency lists |
| AI/ML container | model integrity and inference surface | may receive SBOM, CBOM, and VEX when it is a tracked runtime |

## What Is Modeled In DSL

The DSL carries only lightweight metadata for selected containers:

- `arch.ref`
- `bom.enabled`
- `bom.ref`
- `runtime.unit`
- `sbom.scope`
- `cbom.scope`
- `vex.scope`
- `asset.criticality`
- `deployment.zone`

The selected containers also receive the tag:

- `Supply Chain Tracked`

This keeps the DSL architecture-centric while still giving automation a stable mapping.

## What Moves Into The Policy File

The policy file carries information that is important, but less architectural than the model shape itself:

- `subject_type`
- `supplier.name`
- `supplier.type`
- artifact applicability and status
- artifact origin
- exploitability context
- cyber-physical flags
- AI relevance
- future scanner or advisory source hints
- maturity transition rules
- freshness thresholds

## What Moves Into The Evidence File

The evidence file carries:

- evidence source references
- evidence kinds
- adapter declarations for selected local input shapes
- collection method
- evidence scope
- content status
- binding state
- maturity and confidence
- last verified timestamp or placeholder
- evidence limitations

## What Is Generated Outside The DSL

Outside the DSL, the repository generates:

- CycloneDX SBOM scaffolds
- CycloneDX CBOM scaffolds
- CycloneDX VEX scaffolds
- a BOM manifest listing which containers are in scope
- coverage reports showing architecture-to-supply-chain coverage
- evidence reports showing how each artifact type could later be supported

The generated files are derived from [`../../model/workspace.json`](../../model/workspace.json), not from direct package scanning.

## What Is Stored In Git

Tracked in Git:

- authored DSL metadata
- generated `workspace.json`
- supply-chain mapping docs
- generator script
- generated BOM scaffolds and manifest

Remains derived:

- the BOM artifacts are convenience outputs that can be regenerated from the model

## Metadata Convention

The convention in this repository is:

| Property | Meaning |
| --- | --- |
| `arch.ref` | stable architecture identity used to link the DSL to the policy file |
| `bom.enabled` | whether a container participates in BOM generation |
| `bom.ref` | stable artifact subject identifier used in generated CycloneDX files |
| `runtime.unit` | deployable or runtime unit name represented by the BOM |
| `sbom.scope` | intended SBOM scope for that runtime |
| `cbom.scope` | intended CBOM scope, or `none` if not needed |
| `vex.scope` | intended VEX attachment scope |
| `asset.criticality` | architecture-level criticality used for prioritization |
| `deployment.zone` | edge, fog, or cloud placement used for governance context |

## Example DSL Pattern

```dsl
apiGateway = container "API Gateway" "Centralized API management with versioning and contract enforcement" "Kong/AWS API Gateway" {
    tags "Cloud Service,API Management,Medium Risk,Cloud Zone,Supply Chain Tracked"
    url https://github.com/your-repo/api-gateway
    properties {
        "arch.ref" "smartparking.arch.container.api-gateway"
        "bom.enabled" "true"
        "bom.ref" "smartparking.bom.api-gateway"
        "runtime.unit" "cloud-api-gateway"
        "sbom.scope" "deployable-unit"
        "cbom.scope" "tls-termination-and-token-validation"
        "vex.scope" "internet-facing-runtime"
        "asset.criticality" "high"
        "deployment.zone" "cloud"
    }
}
```

## Policy File Pattern

The policy file defines how architecture subjects become supply-chain subjects:

```json
{
  "arch_ref": "smartparking.arch.container.gateway-service",
  "element_name": "Gateway Service",
  "bom_ref": "smartparking.bom.gateway-service",
  "runtime_unit": "edge-gateway-service",
  "subject_type": "cyber-physical-runtime",
  "supplier": {
    "name": "Smart Parking Platform Team",
    "type": "first-party"
  },
  "artifacts": {
    "sbom": {"applicable": true, "status": "scaffolded", "origin": "architecture-derived-scaffold"},
    "cbom": {"applicable": true, "status": "scaffolded", "origin": "architecture-derived-scaffold"},
    "vex": {
      "applicable": true,
      "status": "scaffolded",
      "origin": "architecture-derived-scaffold",
      "exploitability_context": "edge gateway in the gate-control path; compromise could affect physical actions."
    }
  },
  "domain_flags": {
    "cyber_physical_criticality": "high",
    "physical_control": "direct",
    "safety_impact": "high",
    "ai_decision_role": "supporting",
    "internet_exposure": "indirect",
    "privilege_level": "device-control",
    "handles_secrets": true
  }
}
```

## Evidence File Pattern

The evidence file defines how future proof can attach to those subjects:

```json
{
  "arch_ref": "smartparking.arch.container.gateway-service",
  "bom_ref": "smartparking.bom.gateway-service",
  "runtime_unit": "edge-gateway-service",
  "evidence_subjects": [
    {
      "evidence_subject_id": "gateway-runtime",
      "subject_variant": "runtime_service",
      "artifact_evidence": {
        "sbom": {
          "content_status": "scaffolded",
          "binding_state": "planned",
          "evidence_scope": "runtime-unit",
          "sources": [
            {
              "evidence_kind": "scanner_output",
              "source_type": "container-image-sbom",
              "collection_method": "scanner_derived",
              "reference": "placeholder://edge-gateway-service/image-sbom.cdx.json",
              "maturity": "planned",
              "confidence": "low",
              "last_verified": "not-verified",
              "limitations": "Placeholder binding only; no scanner output committed."
            }
          ]
        }
      }
    }
  ]
}
```

## Transition And Freshness Rules

Milestone 4 adds policy-governed rules for:

- `scaffolded`
- `partially_evidenced`
- `evidence_backed`
- `not_applicable`

and freshness states:

- `fresh`
- `stale`
- `expired`
- `unknown`
- `not_applicable`

The rules stay in the policy layer because they are governance logic, not evidence facts.

In this repository:

- a linked source can be enough for `partially_evidenced`
- `evidence_backed` requires a stricter rule, including non-placeholder references
- VEX requires an `advisory_reviewed` source before it can move upward
- freshness is derived from `last_verified` relative to the configured evaluation date

Milestone 5 adds:

- admissible evidence kinds per artifact type
- precedence order across multiple sources
- support for one architecture subject to decompose into multiple evidence subjects

Milestone 6 adds:

- lightweight evidence adapters for selected local file shapes
- owner and review cadence in the policy layer
- review status on evidence subjects

## One Limited Decomposition Example

Gateway Service now demonstrates one architecture subject decomposing into multiple evidence subjects:

- `gateway-runtime`
- `gateway-control-profile`

That decomposition is intentionally small but useful:

- SBOM-style runtime evidence stays attached to the runtime subject
- CBOM-supporting control evidence stays attached to the control-profile subject

`Edge AI Runtime` shows a second pattern:

- `edge-ai-runtime-service`
- `edge-ai-model-package`

That keeps runtime evidence and model-package evidence separate without expanding the architecture scope.

## Admissibility And Precedence

Milestone 5 also distinguishes artifact type from evidence kind.

Examples:

- `sbom` may accept `scanner_output`, `package_manifest`, or `imported_artifact`
- `cbom` may accept `crypto_policy`, `repo_control_document`, or `deployment_manifest`
- `vex` requires `advisory_record`
- `provenance` may accept `attestation`, `deployment_manifest`, or `imported_artifact`

If multiple admissible sources exist, the policy file defines precedence.

Current teaching example:

- Gateway Service CBOM has both `repo_control_document` and `crypto_policy`
- both are supporting evidence for a partial state
- `crypto_policy` wins selection because it is higher in the configured precedence order

Milestone 6 adds a second teaching example:

- Gateway Service SBOM has a real local imported CycloneDX file
- that file is normalized through the `cyclonedx_json` adapter
- it becomes the selected source and drives an `evidence_backed` state under the current rules

and a third:

- API Gateway VEX has a real local advisory-review record
- that file is normalized through the `advisory_record` adapter
- it becomes a `partially_evidenced` source without claiming a supplier-issued VEX document

## CBOM Strategy

CBOM is attached only to containers with explicit cryptographic or trust-material relevance.

In this milestone that means:

- Gateway Service
- Edge AI Runtime
- API Gateway
- Identity Provider
- Secrets Manager

The Event Bus receives SBOM and VEX scaffolds, but no CBOM scaffold, because the first milestone does not treat it as a primary cryptographic boundary.

## External Providers

External providers stay modeled as external software systems in Structurizr. They are not expanded into fake dependency inventories.

This means:

- architecture still shows who the system depends on
- BOM files remain focused on local deployable units
- future scanner-backed enrichment can add supplier/package details later

## Current Milestone Scope

The current milestone intentionally tracks only six containers. This keeps the repository understandable while proving the pattern:

- enough variety to cover edge, cloud, AI, identity, secrets, and messaging
- small enough that readers can understand the mapping quickly
- useful enough to support later scanner-backed evolution

## Verification

Use:

```bash
python3 tools/generate_cyclonedx_artifacts.py
python3 tools/generate_cyclonedx_artifacts.py --check
```

The `--check` mode verifies that the tracked CycloneDX scaffolds match what the current `workspace.json` and metadata would generate.
It also verifies that the policy file and evidence file point only to known tracked architecture subjects.
