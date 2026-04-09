# Technical View Based On `workspace.dsl` And `workspace.json`

## Why Both Files Matter

### `workspace.dsl`

This is the authored architecture model. It contains:

- model definitions
- relationships
- deployment
- views
- styles

It is the right file for architects and maintainers.

Reference:

- [`model/workspace.dsl`](../model/workspace.dsl)

### `workspace.json`

This is the resolved/exported workspace model. It is useful for:

- programmatic parsing
- extracting inventories
- validating deployment nodes and container instances
- driving tooling or visualizations

Reference:

- [`model/workspace.json`](../model/workspace.json)

## Technical Architecture In The Model

## API And User Entry

- `Driver -> API Gateway` over `HTTPS`
- `Administrator -> API Gateway` over `HTTPS`
- `API Gateway` routes to:
  - `Mobile API`
  - `Management Dashboard`
  - `ANPR Service`
  - `Access Control Service`
  - `Parking Space Management`
  - `Payment Service`

References:

- [`model/workspace.dsl:319`](../model/workspace.dsl#L319)
- [`model/workspace.dsl:323`](../model/workspace.dsl#L323)

## Event-Driven Backbone

The model uses `Event Bus` with Kafka for event-driven flows:

- gateway publishes `license_plate_read`
- gateway publishes `gate_opened`
- gateway publishes `space_occupied`
- downstream consumers include ANPR, access control, parking, payment, and AI analytics

References:

- [`model/workspace.dsl:345`](../model/workspace.dsl#L345)
- [`model/workspace.dsl:349`](../model/workspace.dsl#L349)

## Data And AI Lifecycle

The technical data flow is:

1. operational data flows into `Data Fabric`
2. historical data lands in `Data Lake`
3. `MLOps Pipeline` reads training data
4. `Model Registry` stores model artifacts
5. `Model Serving` and `Edge AI Runtime` consume model versions
6. `Model Monitoring` and `AI Metrics Collector` observe model behavior

References:

- [`model/workspace.dsl:355`](../model/workspace.dsl#L355)
- [`model/workspace.dsl:360`](../model/workspace.dsl#L360)
- [`model/workspace.dsl:366`](../model/workspace.dsl#L366)

## Edge Technical Stack

The edge side is not a single box. The model includes:

- `Edge Orchestrator` on `K3s`
- `ANPR Service`
- `Gateway Service`
- `Edge AI Runtime`
- `Edge Storage`
- `Security Gateway`
- `Protocol Adapter Manager`

The physical edge environment also includes:

- `Camera Network` on `ONVIF`
- `Gate Controller` on `Modbus`

References:

- [`model/workspace.dsl:661`](../model/workspace.dsl#L661)
- [`model/workspace.dsl:670`](../model/workspace.dsl#L670)
- [`model/workspace.dsl:676`](../model/workspace.dsl#L676)

## Gateway Technical Internals

The gateway has the richest technical decomposition in the model. It includes protocol ingestion, schema validation, device identity, filtering, anomaly detection, plugin loading, and runtime execution.

This is the most technically important service in the whole model because it bridges:

- cameras and device traffic
- industrial control
- standardized event publication
- security validation

References:

- [`model/workspace.dsl:43`](../model/workspace.dsl#L43)
- [`model/workspace.dsl:571`](../model/workspace.dsl#L571)

## Zero-Trust Technical Controls

The technical control plane includes:

- OAuth2 client credentials from `Identity Provider`
- X.509 certificates from `Certificate Authority`
- authorization from `Policy Engine`
- protocol validation from `Security Gateway`
- storage encryption from `Encryption Service`
- secret distribution from `Secrets Manager`

References:

- [`model/workspace.dsl:408`](../model/workspace.dsl#L408)
- [`model/workspace.dsl:418`](../model/workspace.dsl#L418)
- [`model/workspace.dsl:424`](../model/workspace.dsl#L424)
- [`model/workspace.dsl:431`](../model/workspace.dsl#L431)
- [`model/workspace.dsl:527`](../model/workspace.dsl#L527)

## Observability Technical Stack

The model includes:

- `Metrics Collector`
- `Log Aggregator`
- `Tracing Platform`
- `Observability Dashboard`
- `AI Metrics Collector`
- `Alerting System`

This is not just ops detail. It is part of the technical architecture because it carries performance, audit, and AI confidence telemetry.

References:

- [`model/workspace.dsl:452`](../model/workspace.dsl#L452)
- [`model/workspace.dsl:460`](../model/workspace.dsl#L460)
- [`model/workspace.dsl:467`](../model/workspace.dsl#L467)
- [`model/workspace.dsl:476`](../model/workspace.dsl#L476)

## Extensibility Technical Stack

The model includes a platform extension layer:

- `Plugin Framework`
- `Plugin Registry`
- `Protocol Adapter Manager`
- `Extension API`
- `AI Pipeline API`
- `Data Sink Manager`

This is technically important because extensibility is a real attack surface. A plugin-capable platform needs stronger validation and signing than a closed platform.

References:

- [`model/workspace.dsl:550`](../model/workspace.dsl#L550)
- [`model/workspace.dsl:565`](../model/workspace.dsl#L565)

## What Engineers Can Do With `workspace.json`

- enumerate deployment nodes and container instances
- build reports of all containers by tag
- extract all high-risk relationships
- trace security-service dependencies
- validate that views cover the intended threat paths

## Bottom Line

The technical side of this architecture is in the model itself:

- protocols are explicit
- service boundaries are explicit
- deployment targets are explicit
- security relationships are explicit
- attack paths are explicit

That is why both `workspace.dsl` and `workspace.json` belong inside this package.
