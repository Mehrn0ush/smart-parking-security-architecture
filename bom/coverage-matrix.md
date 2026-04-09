# Supply-Chain Coverage Matrix

This file is generated from the architecture, policy, and decomposed evidence subject layers.

| architecture_subject | runtime_unit | deployment_zone | criticality | subject_type | owner | review_cadence | sbom | cbom | vex | generated_files |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| API Gateway | cloud-api-gateway | cloud | high | internet-facing-runtime | platform-edge-team | monthly | scaffolded | scaffolded | partially_evidenced | bom/sbom/api-gateway.cdx.json; bom/cbom/api-gateway.cdx.json; bom/vex/api-gateway.cdx.json |
| Edge AI Runtime | edge-ai-runtime | edge | high | ai-edge-runtime | ai-team | monthly | scaffolded | scaffolded | scaffolded | bom/sbom/edge-ai-runtime.cdx.json; bom/cbom/edge-ai-runtime.cdx.json; bom/vex/edge-ai-runtime.cdx.json |
| Event Bus | cloud-event-bus | cloud | high | platform-service | data-platform-team | quarterly | scaffolded | not_applicable | scaffolded | bom/sbom/event-bus.cdx.json; bom/vex/event-bus.cdx.json |
| Gateway Service | edge-gateway-service | edge | high | cyber-physical-runtime | platform-team | monthly | evidence_backed | partially_evidenced | scaffolded | bom/sbom/gateway-service.cdx.json; bom/cbom/gateway-service.cdx.json; bom/vex/gateway-service.cdx.json |
| Identity Provider | cloud-identity-provider | cloud | high | identity-runtime | identity-team | monthly | scaffolded | scaffolded | scaffolded | bom/sbom/identity-provider.cdx.json; bom/cbom/identity-provider.cdx.json; bom/vex/identity-provider.cdx.json |
| Secrets Manager | cloud-secrets-manager | cloud | high | secret-management-runtime | trust-team | monthly | scaffolded | scaffolded | scaffolded | bom/sbom/secrets-manager.cdx.json; bom/cbom/secrets-manager.cdx.json; bom/vex/secrets-manager.cdx.json |

Coverage states are rule-derived. They only count as real evidence-backed when a non-placeholder, admissible input is actually attached.
