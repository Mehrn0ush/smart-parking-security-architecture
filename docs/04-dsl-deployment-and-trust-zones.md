# Deployment And Trust Zones From `workspace.dsl`

## Production Deployment Topology

The `Production` deployment environment is modeled explicitly in the DSL.

Reference:

- [`workspace.dsl:659`](../model/workspace.dsl#L659)

## Edge Layer

Modeled in `Edge Cluster`:

- `Edge Orchestrator`
- `ANPR Service`
- `Gateway Service`
- `Edge AI Runtime`
- `Edge Storage`
- `Security Gateway`
- `Protocol Adapter Manager`

It also includes physical infrastructure nodes:

- `Entrance Camera`
- `Exit Camera`
- `Parking Area Cameras`
- `Entry Gate`
- `Exit Gate`

References:

- [`workspace.dsl:661`](../model/workspace.dsl#L661)
- [`workspace.dsl:670`](../model/workspace.dsl#L670)
- [`workspace.dsl:676`](../model/workspace.dsl#L676)

## Fog Layer

Modeled in `Fog Cluster`:

- `Fog Gateway`

Reference:

- [`workspace.dsl:683`](../model/workspace.dsl#L683)

## Cloud Layer

Modeled under `Cloud Provider` with dedicated deployment nodes for:

- API management
- data management
- event bus
- microservices
- MLOps
- OTA management
- security infrastructure
- observability
- configuration
- extension platform
- database
- data lake
- object storage
- web frontend

Reference:

- [`workspace.dsl:687`](../model/workspace.dsl#L687)

## Security Implications

### The edge is physically exposed and operationally critical

The deployment model places the gateway, ANPR, AI runtime, and physical camera and gate infrastructure together. That means edge compromise can have immediate real-world impact.

### The cloud security plane is separated as its own node

The model groups:

- `Identity Provider`
- `Certificate Authority`
- `Policy Engine`
- `Security Monitoring`
- `Encryption Service`

under `Security Server`, which is a clear architectural statement that security infrastructure is a platform capability, not hidden inside applications.

Reference:

- [`workspace.dsl:721`](../model/workspace.dsl#L721)

### The model differentiates operational planes

The deployment separates:

- application plane
- ML plane
- security plane
- observability plane
- configuration plane
- platform extensibility plane

That separation is useful for both threat containment and operational ownership.
