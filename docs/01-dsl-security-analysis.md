# Security Analysis Based On `workspace.dsl`

## Scope

This analysis is based directly on the Structurizr model in [`workspace.dsl`](../model/workspace.dsl), not on the surrounding summaries.

## What The DSL Explicitly Models Well

### Threat actors are first-class model elements

The DSL defines four threat actors:

- `External Attacker`
- `Malicious Insider`
- `Script Kiddie`
- `Nation State Actor`

These are not mentioned only in prose. They are modeled as people with tags and then connected through explicit attack relationships. That is a strong security-architecture move because the attack model is part of the architecture model itself.

References:

- [`workspace.dsl:15`](../model/workspace.dsl#L15)
- [`workspace.dsl:619`](../model/workspace.dsl#L619)

### Trust zoning is embedded in tags

The model uses `Internet Zone`, `Edge Zone`, `Fog Zone`, and `Cloud Zone` tags, and styles them separately. This means trust boundaries are part of the modeled language, not just a diagram annotation.

References:

- [`workspace.dsl:17`](../model/workspace.dsl#L17)
- [`workspace.dsl:35`](../model/workspace.dsl#L35)
- [`workspace.dsl:85`](../model/workspace.dsl#L85)
- [`workspace.dsl:91`](../model/workspace.dsl#L91)
- [`workspace.dsl:932`](../model/workspace.dsl#L932)

### The gateway is modeled as the main cyber-physical choke point

The `Gateway Service` is decomposed into components including:

- `Modbus Security Wrapper`
- `Modbus Protocol Filter`
- `Modbus Anomaly Detector`
- `Device Certificate Manager`
- `Security Validator`
- `Auth Handler`

That makes the most critical boundary in the platform explicit: the path from digital requests to industrial control behavior.

References:

- [`workspace.dsl:39`](../model/workspace.dsl#L39)
- [`workspace.dsl:47`](../model/workspace.dsl#L47)
- [`workspace.dsl:48`](../model/workspace.dsl#L48)
- [`workspace.dsl:49`](../model/workspace.dsl#L49)
- [`workspace.dsl:50`](../model/workspace.dsl#L50)

### Zero-trust services are explicit containers

The DSL models a dedicated zero-trust stack:

- `Identity Provider`
- `Certificate Authority`
- `Policy Engine`
- `Security Gateway`
- `Security Monitoring`
- `Encryption Service`
- `Secrets Manager`

This is stronger than simply saying “zero trust” in a document.

References:

- [`workspace.dsl:164`](../model/workspace.dsl#L164)
- [`workspace.dsl:169`](../model/workspace.dsl#L169)
- [`workspace.dsl:174`](../model/workspace.dsl#L174)
- [`workspace.dsl:73`](../model/workspace.dsl#L73)
- [`workspace.dsl:180`](../model/workspace.dsl#L180)
- [`workspace.dsl:185`](../model/workspace.dsl#L185)
- [`workspace.dsl:245`](../model/workspace.dsl#L245)

### AI security is part of the model, not an add-on

The DSL includes:

- `Edge AI Runtime`
- `MLOps Pipeline`
- `Model Registry`
- `Model Serving`
- `Model Monitoring`
- `AI Analytics Service`
- AI-specific attack path from `Nation State Actor` to `Edge AI Runtime`
- AI-specific observability through `AI Metrics Collector`

References:

- [`workspace.dsl:58`](../model/workspace.dsl#L58)
- [`workspace.dsl:130`](../model/workspace.dsl#L130)
- [`workspace.dsl:135`](../model/workspace.dsl#L135)
- [`workspace.dsl:140`](../model/workspace.dsl#L140)
- [`workspace.dsl:145`](../model/workspace.dsl#L145)
- [`workspace.dsl:629`](../model/workspace.dsl#L629)

## Main Security-Architecture Findings

### Strongest architectural decision

The strongest decision in the DSL is to put security controls directly around the edge and control-plane boundaries rather than only around public APIs. That is correct for a smart parking system.

### Most critical modeled risk

The most critical modeled risk is the edge gateway path. The DSL itself signals this:

- gateway is tagged `High Risk`
- gateway has security-specific components
- external attacker is connected directly to gateway
- deployment model places gateway near camera and gate-controller infrastructure

References:

- [`workspace.dsl:40`](../model/workspace.dsl#L40)
- [`workspace.dsl:623`](../model/workspace.dsl#L623)
- [`workspace.dsl:661`](../model/workspace.dsl#L661)

### Most advanced modeled area

The most advanced area is the combination of AI/ML lifecycle plus security monitoring and observability. The model does a better job here than many typical IoT architectures.

### Biggest remaining gap in the DSL

The DSL models many controls as relationships, but it does not model enforcement conditions in detail. For example, the existence of a `Policy Engine` is modeled, but the actual authorization decisions, fail-closed behavior, rollback approval, and command semantics are outside the DSL.

That is not a flaw in Structurizr itself. It just means the architecture needs companion artifacts such as policy files, runbooks, and deployment guardrails.
