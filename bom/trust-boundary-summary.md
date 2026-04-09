# Trust-Boundary Summary

This file highlights governance posture around the most sensitive trust-boundary categories in the architecture model.

## ai_ml_provenance_sensitive

- Edge AI Runtime / provenance: governed=partially_evidenced, freshness=expired, approval_state=expired, review_blocking=true, escalation_required=true, waiver_active=false, provenance_assurance=reference_only
- Event Bus / vex: governed=scaffolded, freshness=unknown, approval_state=not_applicable, review_blocking=false, escalation_required=true, waiver_active=false, provenance_assurance=not-applicable
- Gateway Service / sbom: governed=partially_evidenced, freshness=fresh, approval_state=expired, review_blocking=true, escalation_required=true, waiver_active=false, provenance_assurance=not-applicable
## cyber_physical_control

- Gateway Service / sbom: governed=partially_evidenced, freshness=fresh, approval_state=expired, review_blocking=true, escalation_required=true, waiver_active=false, provenance_assurance=not-applicable
## identity

- Identity Provider / cbom: governed=scaffolded, freshness=unknown, approval_state=not_applicable, review_blocking=true, escalation_required=false, waiver_active=true, provenance_assurance=not-applicable
## secrets

- Gateway Service / sbom: governed=partially_evidenced, freshness=fresh, approval_state=expired, review_blocking=true, escalation_required=true, waiver_active=false, provenance_assurance=not-applicable
- Identity Provider / cbom: governed=scaffolded, freshness=unknown, approval_state=not_applicable, review_blocking=true, escalation_required=false, waiver_active=true, provenance_assurance=not-applicable
- Secrets Manager / cbom: governed=scaffolded, freshness=unknown, approval_state=not_applicable, review_blocking=true, escalation_required=true, waiver_active=false, provenance_assurance=not-applicable
- Secrets Manager / vex: governed=partially_evidenced, freshness=expired, approval_state=not_applicable, review_blocking=false, escalation_required=true, waiver_active=false, provenance_assurance=not-applicable
