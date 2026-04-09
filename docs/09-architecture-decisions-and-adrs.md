# Architecture Decisions And ADRs

## Why ADRs Matter

Architectural Decision Records explain why a system chose one direction and not another. They are especially useful for students and junior engineers because they show tradeoffs, not just outcomes.

## Relevant ADRs Included In This Package

- [`adrs/ADR-001-microservices-architecture.md`](adrs/ADR-001-microservices-architecture.md)
- [`adrs/ADR-002-hybrid-edge-cloud-architecture.md`](adrs/ADR-002-hybrid-edge-cloud-architecture.md)
- [`adrs/ADR-004-mqtt-asynchronous-communication.md`](adrs/ADR-004-mqtt-asynchronous-communication.md)
- [`adrs/ADR-005-data-first-architecture.md`](adrs/ADR-005-data-first-architecture.md)
- [`adrs/ADR-006-zero-trust-security-model.md`](adrs/ADR-006-zero-trust-security-model.md)
- [`adrs/ADR-007-observability-stack.md`](adrs/ADR-007-observability-stack.md)
- [`adrs/ADR-008-ai-ml-integration-framework.md`](adrs/ADR-008-ai-ml-integration-framework.md)
- [`adrs/ADR-010-ATLAS-Integration.md`](adrs/ADR-010-ATLAS-Integration.md)

## How They Connect To The DSL

- microservices ADR explains the service split shown in the container model
- hybrid edge/cloud ADR explains the edge, fog, and cloud deployment
- layered messaging ADR explains why Kafka is the platform event backbone while MQTT is used at the edge
- data-first ADR explains schema registry, ontology, and data fabric
- zero-trust ADR explains identity, certificates, policy, and security gateway
- observability ADR explains metrics, logs, tracing, AI metrics, and alerts
- AI/ML integration ADR explains model registry, serving, monitoring, and edge runtime
- ATLAS ADR explains why AI-specific threat paths belong in the architecture

## Teaching Guidance

When you review the DSL, do not ask only “what is here?” Also ask:

- what decision caused this element to exist?
- what risk was the team trying to reduce?
- what cost or complexity came with that decision?
