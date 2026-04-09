# Governance And Operating Model

## Why Governance Belongs In Architecture Documentation

Students and junior engineers often see architecture as boxes and arrows only. That is incomplete. In a system with AI, payments, physical gates, secrets, and OTA updates, governance determines who is allowed to change what, approve what, and respond to what.

## Core Governance Domains

### Security Governance

Owners:

- security architecture
- identity and access standards
- secrets management policy
- incident response standards

Expected decisions:

- minimum controls for edge devices
- required signing and certificate rules
- logging and retention requirements

### AI Governance

Owners:

- model approval
- dataset lineage and provenance
- adversarial testing requirements
- drift and rollback rules

Expected decisions:

- when a model can move to production
- when a model must be rolled back
- what evidence is required for AI releases

### Platform Governance

Owners:

- plugin registration
- extension review
- protocol adapter acceptance
- OTA and environment promotion rules

Expected decisions:

- who can publish plugins
- who can approve new adapters
- how external integrations are isolated

### Data Governance

Owners:

- retention rules
- privacy boundaries
- lawful use of license plate and location data
- access to data lake and operational databases

Expected decisions:

- how long ANPR evidence is retained
- who can query historical movement data
- how data is classified and masked

## Governance Mapped To The Model

The DSL already points to the governing control points:

- `Identity Provider`
- `Certificate Authority`
- `Policy Engine`
- `Secrets Manager`
- `MLOps Pipeline`
- `Model Registry`
- `OTA Manager`
- `Plugin Registry`
- `Environment Manager`

Reference:

- [`../model/workspace.dsl`](../model/workspace.dsl)

## Operating Model For Teams

Recommended split for a real implementation:

- platform team owns core runtime, deployment, observability, and plugin framework
- security team owns identity, policy, certificates, secrets, and monitoring standards
- AI/ML team owns models, data lineage, validation, and monitoring thresholds
- product teams own business services such as parking, access control, and payment

## What Juniors Should Understand

- governance is how architecture stays true over time
- controls without owners become optional
- architecture without approval paths becomes drift
- security incidents are often failures of governance, not only failures of code

