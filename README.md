# Smart Parking Security Architecture in the AI Age

Recommended repository name: `smart-parking-security-architecture`

This project is a learning-focused, DSL-grounded architecture package for people who want to understand how to design, analyze, and govern a secure Smart Parking platform in the AI age.

It is built around a real Structurizr model, not a fictional whitepaper. The core source of truth is:

- [`model/workspace.dsl`](model/workspace.dsl)
- [`model/workspace.json`](model/workspace.json)

The package explains how to reason about a modern Smart Parking system that includes:

- mobile and admin entry points
- edge ANPR and edge AI
- gateway-to-gate cyber-physical control paths
- event-driven cloud services
- AI/ML lifecycle management
- zero-trust identity, policy, and secrets
- observability, governance, and operating controls

## Purpose

Most architecture repositories either:

- show a diagram without explaining why the design exists, or
- contain many technical files without a usable learning path

This project exists to close that gap.

Its purpose is to help readers understand:

1. what a secure Smart Parking architecture looks like
2. why the gateway, edge AI, identity, secrets, and data lake are critical control points
3. how AI changes security architecture, governance, and operations
4. how architectural decisions can be traced to an explicit system model

## Who This Is For

This repository is designed for:

- students learning software architecture, cybersecurity, or AI systems
- junior engineers who need a guided example of a real architecture model
- solution and security architects studying cyber-physical and AI-enabled platforms
- platform, IoT, and AI/ML engineers who want a structured reference

## What You Will Learn

By working through this project, you should learn how to:

- read a Structurizr DSL model as an architecture source of truth
- separate internet, edge, fog, and cloud trust zones
- identify the highest-risk attack paths in a cyber-physical system
- understand why ANPR and edge AI introduce new security concerns
- connect architecture, governance, and operations instead of treating them separately
- translate architecture into model-driven technical artifacts
- relate architecture metadata to SBOM, CBOM, and VEX without replacing the C4 model

## What Makes This Project Different

This is not just a diagram collection.

It combines:

- an authored Structurizr DSL model
- an exported JSON model for tooling and automation
- security architecture analysis tied directly to the DSL
- technical walkthroughs for engineers
- governance and operating-model guidance
- ADR references explaining why major decisions exist
- runnable scripts for model sync, verification, and model-driven AI risk generation
- architecture-aware CycloneDX scaffolds linked to selected runtime units
- included ADRs so the package can stand on its own

## Project Structure

### Core model

- [`model/workspace.dsl`](model/workspace.dsl): authored Structurizr source model
- [`model/workspace.json`](model/workspace.json): exported workspace model for tooling
- [`model/manifest.json`](model/manifest.json): generated sync metadata and hashes
- [`model/supply-chain-mapping.yaml`](model/supply-chain-mapping.yaml): policy layer for runtime subjects, artifact applicability, and maturity
- [`model/supply-chain-evidence.yaml`](model/supply-chain-evidence.yaml): evidence bindings layer for future scanner, provenance, and advisory sources
- [`evidence/README.md`](evidence/README.md): small real input files used by the milestone 6 evidence adapters

### Supply-chain artifacts

- [`bom/README.md`](bom/README.md): how CycloneDX artifacts relate to the architecture
- [`bom/manifest.json`](bom/manifest.json): generated index of tracked BOM scopes
- [`bom/coverage-matrix.md`](bom/coverage-matrix.md): generated architecture-to-supply-chain coverage summary
- [`bom/coverage-matrix.csv`](bom/coverage-matrix.csv): generated machine-readable coverage summary
- [`bom/evidence-matrix.md`](bom/evidence-matrix.md): generated evidence-binding summary
- [`bom/evidence-matrix.csv`](bom/evidence-matrix.csv): generated machine-readable evidence-binding summary
- [`bom/sbom/`](bom/sbom): generated CycloneDX SBOM scaffolds
- [`bom/cbom/`](bom/cbom): generated CycloneDX CBOM scaffolds for crypto-relevant containers
- [`bom/vex/`](bom/vex): generated CycloneDX VEX scaffolds

### Learning and architecture documentation

- [`docs/00-learning-path.md`](docs/00-learning-path.md): recommended reading order
- [`docs/01-dsl-security-analysis.md`](docs/01-dsl-security-analysis.md): security architect reading of the DSL
- [`docs/02-dsl-inventory.md`](docs/02-dsl-inventory.md): inventory of actors, containers, and key flows
- [`docs/03-dsl-attack-paths.md`](docs/03-dsl-attack-paths.md): attack-path analysis from the modeled relationships
- [`docs/04-dsl-deployment-and-trust-zones.md`](docs/04-dsl-deployment-and-trust-zones.md): deployment and trust-boundary walkthrough
- [`docs/05-github-packaging-notes.md`](docs/05-github-packaging-notes.md): packaging guidance for public sharing
- [`docs/06-technical-view.md`](docs/06-technical-view.md): technical architecture view for engineers
- [`docs/07-architecture-principles.md`](docs/07-architecture-principles.md): design principles behind the system
- [`docs/08-governance-and-operating-model.md`](docs/08-governance-and-operating-model.md): governance and team ownership model
- [`docs/09-architecture-decisions-and-adrs.md`](docs/09-architecture-decisions-and-adrs.md): ADR mapping and decision guidance
- [`docs/10-model-sync-workflow.md`](docs/10-model-sync-workflow.md): how to keep the packaged model consistent
- [`docs/supply-chain/README.md`](docs/supply-chain/README.md): why Structurizr and CycloneDX are related but not the same
- [`docs/supply-chain/mapping-spec.md`](docs/supply-chain/mapping-spec.md): mapping rules for SBOM, CBOM, and VEX
- [`docs/supply-chain/evidence-model.md`](docs/supply-chain/evidence-model.md): how evidence bindings work and how to interpret evidence maturity
- [`docs/supply-chain/evidence-adapters.md`](docs/supply-chain/evidence-adapters.md): how local evidence input files are normalized and reviewed

### Included ADRs

- [`docs/adrs/ADR-001-microservices-architecture.md`](docs/adrs/ADR-001-microservices-architecture.md)
- [`docs/adrs/ADR-002-hybrid-edge-cloud-architecture.md`](docs/adrs/ADR-002-hybrid-edge-cloud-architecture.md)
- [`docs/adrs/ADR-004-mqtt-asynchronous-communication.md`](docs/adrs/ADR-004-mqtt-asynchronous-communication.md)
- [`docs/adrs/ADR-005-data-first-architecture.md`](docs/adrs/ADR-005-data-first-architecture.md)
- [`docs/adrs/ADR-006-zero-trust-security-model.md`](docs/adrs/ADR-006-zero-trust-security-model.md)
- [`docs/adrs/ADR-007-observability-stack.md`](docs/adrs/ADR-007-observability-stack.md)
- [`docs/adrs/ADR-008-ai-ml-integration-framework.md`](docs/adrs/ADR-008-ai-ml-integration-framework.md)
- [`docs/adrs/ADR-010-ATLAS-Integration.md`](docs/adrs/ADR-010-ATLAS-Integration.md)

### Diagrams and examples

- [`diagrams/dsl-security-views.md`](diagrams/dsl-security-views.md): derived Mermaid view of the security architecture
- [`code/atlas_risk_matrix.py`](code/atlas_risk_matrix.py): model-driven AI risk report generator using `workspace.json`
- [`code/secure_command_signing_demo.py`](code/secure_command_signing_demo.py): safe teaching demo for signed gate commands
- [`tools/sync_workspace_model.py`](tools/sync_workspace_model.py): sync and verify packaged model artifacts
- [`tools/generate_cyclonedx_artifacts.py`](tools/generate_cyclonedx_artifacts.py): generate and verify architecture-aware CycloneDX scaffolds
- [`run_all.sh`](run_all.sh): one-command entrypoint for users

## Source Of Truth

The source of truth for the architecture is:

- [`model/workspace.dsl`](model/workspace.dsl)

The JSON is included because it is useful for automation and analysis, but it is not the authoring source.

To reduce drift, this package includes:

- [`tools/sync_workspace_model.py`](tools/sync_workspace_model.py)
- [`docs/10-model-sync-workflow.md`](docs/10-model-sync-workflow.md)

`workspace.json` is generated from the packaged DSL with `structurizr-cli`. The package no longer depends on parent-repository files to work.

## Structurizr And CycloneDX

This repository includes a practical architecture-aware integration between the C4 model and CycloneDX.

The rule is intentionally strict:

- Structurizr DSL describes structure, responsibilities, trust zones, and relationships
- [`model/supply-chain-mapping.yaml`](model/supply-chain-mapping.yaml) carries the richer supply-chain policy and subject semantics
- [`model/supply-chain-evidence.yaml`](model/supply-chain-evidence.yaml) carries evidence bindings and provenance expectations
- CycloneDX artifacts are derived governance outputs attached to selected runtime units

That means:

- the DSL does not become a dependency tree
- the policy layer stays outside the DSL so maturity, supplier, and exploitability semantics remain maintainable
- the evidence layer stays outside both DSL and policy because evidence changes with pipelines and reviews
- BOM files do not replace the architecture model
- only high-value containers receive lightweight metadata for BOM generation
- SBOM, CBOM, and VEX stay connected to architecture scope and deployable units
- maturity and freshness are derived from explicit rules, not guessed from prose
- evidence subjects can decompose one architecture subject into multiple runtime or control-oriented evidence views
- evidence kinds and precedence decide which source currently best supports a derived artifact state
- milestone 6 can normalize a small number of real local evidence inputs without turning the repository into a scanner framework
- owner and review cadence are now visible in the generated coverage and evidence outputs
- milestone 7 tracks review at the artifact level and can escalate stale evidence to a handoff owner
- the AI model-package provenance path is now represented by a local provenance-reference record with explicit review and escalation semantics

Start here:

- [`docs/supply-chain/README.md`](docs/supply-chain/README.md)
- [`docs/supply-chain/mapping-spec.md`](docs/supply-chain/mapping-spec.md)
- [`docs/supply-chain/evidence-model.md`](docs/supply-chain/evidence-model.md)
- [`docs/supply-chain/evidence-adapters.md`](docs/supply-chain/evidence-adapters.md)
- [`model/supply-chain-mapping.yaml`](model/supply-chain-mapping.yaml)
- [`model/supply-chain-evidence.yaml`](model/supply-chain-evidence.yaml)
- [`evidence/README.md`](evidence/README.md)
- [`bom/README.md`](bom/README.md)

## Should `workspace.json` Be Tracked?

Recommendation: **yes, keep it tracked**.

Why:

- it makes the package easier to use for students and first-time readers
- scripts such as the AI risk generator can run immediately
- readers can inspect the exported model without installing tooling first
- the package now includes generation and verification so drift is controlled

Important rule:

- `model/workspace.dsl` is the source of truth
- `model/workspace.json` is a generated convenience artifact

If a team wants a stricter source-only repository in the future, `workspace.json` could be made generated-only. For this teaching-oriented GitHub package, keeping it tracked is the better tradeoff.

## First-Time User Onboarding

If this is your first time opening the repository, use this short path.

### 1. Understand the goal

Read this README first, then open:

- [`docs/07-architecture-principles.md`](docs/07-architecture-principles.md)

This explains the big ideas behind the system:

- contract-first boundaries
- edge-to-cloud partitioning
- zero trust
- event-driven integration
- AI as a first-class platform concern
- extensibility with boundaries
- observability as part of architecture

### 2. Understand who owns what

Read:

- [`docs/08-governance-and-operating-model.md`](docs/08-governance-and-operating-model.md)

This is important because Smart Parking is not just a technical system. It is also an operational, security, and AI-governed system.

### 3. Open the real model

Read:

- [`model/workspace.dsl`](model/workspace.dsl)

Focus on:

- threat actors
- edge containers
- gateway components
- security services
- attack relationships
- deployment model
- views

### 4. Read the technical walkthrough

Read:

- [`docs/06-technical-view.md`](docs/06-technical-view.md)

This connects the model to:

- APIs
- Kafka flows
- data and AI lifecycle
- edge deployment
- security control planes
- observability
- plugin/extensibility architecture

### 5. Read the security interpretation

Read:

- [`docs/01-dsl-security-analysis.md`](docs/01-dsl-security-analysis.md)
- [`docs/03-dsl-attack-paths.md`](docs/03-dsl-attack-paths.md)

This shows how a security architect reads the same model.

## Quick Start

From this directory, run:

```bash
bash ./run_all.sh
```

Optional, if you also want the gate-signing demo:

```bash
SMART_PARKING_GATE_DEMO_SECRET='change-me' bash ./run_all.sh
```

## Prerequisites

- Python 3
- `structurizr-cli` available on `PATH`

The package generates `workspace.json` from the packaged `workspace.dsl` using `structurizr-cli`.
It also generates architecture-aware CycloneDX scaffolds plus coverage and evidence matrices under [`bom/`](bom/).

## Structurizr With Docker

If you do not want to install `structurizr-cli` locally, you can use Docker.

### Export `workspace.json` From The DSL

From the package root:

```bash
docker run --rm \
  -v "$PWD:/workspace" \
  structurizr/cli export \
  -workspace /workspace/model/workspace.dsl \
  -format json \
  -output /workspace/model
```

### Run Structurizr Lite To Explore The DSL

From the package root:

```bash
docker run --rm \
  -p 8080:8080 \
  -v "$PWD:/usr/local/structurizr" \
  structurizr/lite
```

Then open:

- `http://localhost:8080`

This is useful if you want to inspect the C4 model visually from the DSL, view multiple diagrams from the single model, and explore the architecture in a way that matches the Structurizr workflow.

## What The One-Command Flow Does

The command:

```bash
bash ./run_all.sh
```

will:

1. sync `model/workspace.dsl` and `model/workspace.json`
2. verify that the packaged JSON matches the DSL-generated JSON
3. generate and verify architecture-aware CycloneDX scaffolds
4. generate a model-driven AI risk report from `workspace.json`
5. optionally run the gate-command signing demo if `SMART_PARKING_GATE_DEMO_SECRET` is set

Note:

- byte-for-byte JSON exports from `structurizr-cli` may differ between runs because some exported identifiers are volatile
- the package therefore verifies semantic equivalence, not raw byte equality

## Expected Outputs

After running the command, you should have:

- synchronized model files under [`model/`](model/)
- verification output confirming the package JSON matches the DSL-generated output
- generated CycloneDX scaffolds under [`bom/`](bom/)
- generated supply-chain coverage reports:
  - [`bom/coverage-matrix.md`](bom/coverage-matrix.md)
  - [`bom/coverage-matrix.csv`](bom/coverage-matrix.csv)
- generated supply-chain evidence reports:
  - [`bom/evidence-matrix.md`](bom/evidence-matrix.md)
  - [`bom/evidence-matrix.csv`](bom/evidence-matrix.csv)
- generated AI risk report:
  - [`data/generated/atlas-risk-report.csv`](data/generated/atlas-risk-report.csv)

If you set `SMART_PARKING_GATE_DEMO_SECRET`, you will also see:

- a successful signed-command verification
- a replay-detection example

## Suggested Learning Tracks

### If you are a student

Start with:

- [`docs/00-learning-path.md`](docs/00-learning-path.md)
- [`docs/07-architecture-principles.md`](docs/07-architecture-principles.md)
- [`docs/08-governance-and-operating-model.md`](docs/08-governance-and-operating-model.md)

### If you are a junior engineer

Start with:

- [`model/workspace.dsl`](model/workspace.dsl)
- [`docs/06-technical-view.md`](docs/06-technical-view.md)
- [`docs/09-architecture-decisions-and-adrs.md`](docs/09-architecture-decisions-and-adrs.md)

### If you are a security architect

Start with:

- [`docs/01-dsl-security-analysis.md`](docs/01-dsl-security-analysis.md)
- [`docs/03-dsl-attack-paths.md`](docs/03-dsl-attack-paths.md)
- [`docs/04-dsl-deployment-and-trust-zones.md`](docs/04-dsl-deployment-and-trust-zones.md)

## Important Safety Notes

- The DSL is the primary source model.
- The JSON is a generated artifact derived from the DSL.
- The supply-chain mapping file is a policy layer, not an architecture source model.
- The supply-chain evidence file is an evidence-binding layer, not proof by itself.
- Derived maturity states such as `partially_evidenced` depend on explicit rule evaluation, source quality, and freshness.
- The AI risk script is model-driven and derives risks from modeled tags, descriptions, technologies, and relationships in `workspace.json`.
- SBOM, CBOM, and VEX files in this repository are scaffold/demo artifacts unless evidence-backed sources are added later.
- The gate-signing demo does not run unless `SMART_PARKING_GATE_DEMO_SECRET` is provided.
- The gate-signing demo is for teaching secure command concepts, not for production deployment.
- The package includes its own ADR copies and no longer depends on the parent repository structure.

## Related Architecture Decisions

Relevant ADRs in the parent repository are summarized in:

- [`docs/09-architecture-decisions-and-adrs.md`](docs/09-architecture-decisions-and-adrs.md)

These ADRs help explain why the model includes:

- microservices
- hybrid edge/cloud design
- MQTT and event-driven integration
- data-first architecture
- zero trust
- observability
- AI/ML integration
- ATLAS-driven AI security thinking

## Recommended Public Repository Name

Primary recommendation:

- `smart-parking-security-architecture`

Other acceptable options:

- `smart-parking-ai-security-architecture`
- `smart-parking-zero-trust-architecture`
- `secure-smart-parking-reference-architecture`

The first option is the strongest because it is:

- clear
- searchable
- broad enough for architecture, governance, and technical guidance
- not tied too narrowly to one framework or one implementation detail
