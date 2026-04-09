# Attention Now

This file highlights the current static attention points across artifact governance.

## approval_expired_now

- Edge AI Runtime / provenance: governed=partially_evidenced, evidence_support=verified, approval_presence=present, approval_state=expired, freshness=expired (approval state is expired; secondary approval is still missing; escalation status is expired-review-required; AI provenance is still reference_only)
- Gateway Service / sbom: governed=partially_evidenced, evidence_support=verified, approval_presence=present, approval_state=expired, freshness=fresh (approval state is expired; governed posture is blocked awaiting approval; escalation status is overdue-review-required)

## blocked_awaiting_approval

- Gateway Service / sbom: governed=partially_evidenced, evidence_support=verified, approval_presence=present, approval_state=expired, freshness=fresh (approval state is expired; governed posture is blocked awaiting approval; escalation status is overdue-review-required)

## dual_review_pending

- Edge AI Runtime / provenance: governed=partially_evidenced, evidence_support=verified, approval_presence=present, approval_state=expired, freshness=expired (approval state is expired; secondary approval is still missing; escalation status is expired-review-required; AI provenance is still reference_only)
- Identity Provider / cbom: governed=scaffolded, evidence_support=none, approval_presence=not_applicable, approval_state=not_applicable, freshness=unknown (secondary approval is still missing; waiver is approaching expiry)
- Secrets Manager / cbom: governed=scaffolded, evidence_support=none, approval_presence=not_applicable, approval_state=not_applicable, freshness=unknown (secondary approval is still missing; escalation status is dual-review-pending)

## escalation_required

- Edge AI Runtime / provenance: governed=partially_evidenced, evidence_support=verified, approval_presence=present, approval_state=expired, freshness=expired (approval state is expired; secondary approval is still missing; escalation status is expired-review-required; AI provenance is still reference_only)
- Event Bus / vex: governed=scaffolded, evidence_support=none, approval_presence=not_applicable, approval_state=not_applicable, freshness=unknown (escalation status is overdue-review-required)
- Gateway Service / sbom: governed=partially_evidenced, evidence_support=verified, approval_presence=present, approval_state=expired, freshness=fresh (approval state is expired; governed posture is blocked awaiting approval; escalation status is overdue-review-required)
- Secrets Manager / cbom: governed=scaffolded, evidence_support=none, approval_presence=not_applicable, approval_state=not_applicable, freshness=unknown (secondary approval is still missing; escalation status is dual-review-pending)
- Secrets Manager / vex: governed=partially_evidenced, evidence_support=verified, approval_presence=not_applicable, approval_state=not_applicable, freshness=expired (escalation status is expired-review-required; expired evidence on a trust-boundary or control-sensitive subject)

## low_assurance_ai_provenance

- Edge AI Runtime / provenance: governed=partially_evidenced, evidence_support=verified, approval_presence=present, approval_state=expired, freshness=expired (approval state is expired; secondary approval is still missing; escalation status is expired-review-required; AI provenance is still reference_only)

## stale_trust_boundary

- Secrets Manager / vex: governed=partially_evidenced, evidence_support=verified, approval_presence=not_applicable, approval_state=not_applicable, freshness=expired (escalation status is expired-review-required; expired evidence on a trust-boundary or control-sensitive subject)

## waiver_expiring_soon

- Identity Provider / cbom: governed=scaffolded, evidence_support=none, approval_presence=not_applicable, approval_state=not_applicable, freshness=unknown (secondary approval is still missing; waiver is approaching expiry)
