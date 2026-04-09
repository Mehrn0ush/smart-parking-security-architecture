# Learning Path

This package is meant to help students and junior engineers move from architecture reading to technical understanding.

## Recommended Order

1. Read [`07-architecture-principles.md`](07-architecture-principles.md) to understand the big design ideas.
2. Read [`08-governance-and-operating-model.md`](08-governance-and-operating-model.md) to understand who owns security, AI, and operations decisions.
3. Read [`09-architecture-decisions-and-adrs.md`](09-architecture-decisions-and-adrs.md) to understand why key choices were made.
4. Open [`../model/workspace.dsl`](../model/workspace.dsl) and locate the main actors, containers, and views.
5. Read [`06-technical-view.md`](06-technical-view.md) to connect the model to protocols, services, and deployment.
6. Read [`supply-chain/README.md`](supply-chain/README.md), [`supply-chain/mapping-spec.md`](supply-chain/mapping-spec.md), [`supply-chain/evidence-model.md`](supply-chain/evidence-model.md), [`supply-chain/evidence-adapters.md`](supply-chain/evidence-adapters.md), [`../model/supply-chain-mapping.yaml`](../model/supply-chain-mapping.yaml), [`../model/supply-chain-evidence.yaml`](../model/supply-chain-evidence.yaml), and [`../evidence/README.md`](../evidence/README.md) to see how architecture scope maps to SBOM, CBOM, VEX, review ownership, and normalized evidence inputs.
7. Read [`01-dsl-security-analysis.md`](01-dsl-security-analysis.md) and [`03-dsl-attack-paths.md`](03-dsl-attack-paths.md) to see how a security architect reads the model.

## What You Should Learn

- how to separate edge, fog, cloud, and internet trust zones
- why the gateway is the main cyber-physical control point
- how AI changes the security architecture
- why governance matters as much as controls
- how architectural decisions become enforceable technical boundaries
- how architecture metadata can drive supply-chain security artifacts without replacing the model
