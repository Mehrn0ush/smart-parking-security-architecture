# Inventory Extracted From `workspace.dsl`

## Threat Actors

Modeled actors:

- `Driver`
- `Administrator`
- `External Attacker`
- `Malicious Insider`
- `Script Kiddie`
- `Nation State Actor`

References:

- [`workspace.dsl:7`](../model/workspace.dsl#L7)
- [`workspace.dsl:11`](../model/workspace.dsl#L11)
- [`workspace.dsl:16`](../model/workspace.dsl#L16)
- [`workspace.dsl:20`](../model/workspace.dsl#L20)
- [`workspace.dsl:24`](../model/workspace.dsl#L24)
- [`workspace.dsl:28`](../model/workspace.dsl#L28)

## Edge Zone Containers

- `ANPR Service`
- `Gateway Service`
- `Edge AI Runtime`
- `Edge Storage`
- `Edge Orchestrator`
- `Security Gateway`
- `Protocol Adapter Manager`

Reference:

- [`workspace.dsl:33`](../model/workspace.dsl#L33)

## Gateway Components

- `RTSP Client`
- `ONVIF Parser`
- `MQTT Publisher`
- `Modbus Translator`
- `Modbus Security Wrapper`
- `Modbus Protocol Filter`
- `Modbus Anomaly Detector`
- `Device Certificate Manager`
- `Schema Validator`
- `Security Validator`
- `Auth Handler`
- `Plugin Loader`
- `Adapter Runtime`

Reference:

- [`workspace.dsl:43`](../model/workspace.dsl#L43)

## Fog Zone Containers

- `Fog Gateway`

Reference:

- [`workspace.dsl:83`](../model/workspace.dsl#L83)

## Cloud Zone And Supporting Containers

- `API Gateway`
- `Schema Registry`
- `Data Fabric`
- `Ontology Service`
- `Event Bus`
- `Access Control Service`
- `Parking Space Management`
- `Payment Service`
- `MLOps Pipeline`
- `Model Registry`
- `Model Serving`
- `Model Monitoring`
- `AI Analytics Service`
- `OTA Manager`
- `Identity Provider`
- `Certificate Authority`
- `Policy Engine`
- `Security Monitoring`
- `Encryption Service`
- `Metrics Collector`
- `Log Aggregator`
- `Tracing Platform`
- `Observability Dashboard`
- `AI Metrics Collector`
- `Alerting System`
- `Infrastructure as Code`
- `Configuration Manager`
- `Deployment Pipeline`
- `Environment Manager`
- `Feature Flag Service`
- `Secrets Manager`
- `Plugin Framework`
- `Plugin Registry`
- `Extension API`
- `AI Pipeline API`
- `Data Sink Manager`
- `Data Lake`
- `Management Dashboard`
- `Mobile API`
- `Metadata Database`
- `Video Storage`

Reference:

- [`workspace.dsl:89`](../model/workspace.dsl#L89)

## External Systems

- `Police Database`
- `Payment Gateway`
- `ERP System`

Reference:

- [`workspace.dsl:303`](../model/workspace.dsl#L303)

## Important Modeled Security Flows

- identity provider distributes OAuth2 client credentials
- certificate authority issues X.509 certificates
- policy engine enforces least-privilege permissions
- security gateway validates protocol translation
- encryption service protects storage systems
- security monitoring observes gateway, ANPR, access control, payment, identity, and policy activity

References:

- [`workspace.dsl:408`](../model/workspace.dsl#L408)
- [`workspace.dsl:418`](../model/workspace.dsl#L418)
- [`workspace.dsl:424`](../model/workspace.dsl#L424)
- [`workspace.dsl:431`](../model/workspace.dsl#L431)
- [`workspace.dsl:436`](../model/workspace.dsl#L436)
- [`workspace.dsl:442`](../model/workspace.dsl#L442)

## Important Modeled Sensitive Data Flows

- `Driver -> API Gateway` tagged `PII,Cardholder,High Risk`
- `Payment Service -> Payment Gateway` tagged `Cardholder,Secrets,High Risk`
- `ANPR Service -> Data Lake` tagged `PII,High Risk`
- `Identity Provider -> Secrets Manager` tagged `Secrets,High Risk`

Reference:

- [`workspace.dsl:644`](../model/workspace.dsl#L644)
