#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


class PackageTests(unittest.TestCase):
    def test_markdown_links_resolve_within_package(self) -> None:
        for md in ROOT.rglob("*.md"):
            text = md.read_text()
            for link in LINK_RE.findall(text):
                if "://" in link or link.startswith("#"):
                    continue
                target_path = (md.parent / link.split("#")[0]).resolve()
                self.assertTrue(target_path.exists(), f"Broken link in {md}: {link}")
                self.assertTrue(str(target_path).startswith(str(ROOT.resolve())), f"External package link in {md}: {link}")

    def test_sync_check_passes(self) -> None:
        subprocess.run(["python3", "tools/sync_workspace_model.py"], cwd=ROOT, check=True, capture_output=True, text=True)
        result = subprocess.run(
            ["python3", "tools/sync_workspace_model.py", "--check"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_ai_risk_report_generates(self) -> None:
        subprocess.run(["python3", "code/atlas_risk_matrix.py"], cwd=ROOT, check=True, capture_output=True, text=True)
        report = ROOT / "data" / "generated" / "atlas-risk-report.csv"
        self.assertTrue(report.exists())
        with report.open(newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertGreater(len(rows), 0)
        self.assertIn("risk_score", rows[0])

    def test_cyclonedx_scaffolds_generate_and_verify(self) -> None:
        subprocess.run(["python3", "tools/generate_cyclonedx_artifacts.py"], cwd=ROOT, check=True, capture_output=True, text=True)
        result = subprocess.run(
            ["python3", "tools/generate_cyclonedx_artifacts.py", "--check"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        manifest = json.loads((ROOT / "bom" / "manifest.json").read_text())
        tracked = manifest["tracked_subjects"]
        self.assertEqual(len(tracked), 6)
        self.assertEqual(manifest["schema_version"], "10.0")
        self.assertEqual(manifest["policy_file"], "model/supply-chain-mapping.yaml")
        self.assertEqual(manifest["evidence_file"], "model/supply-chain-evidence.yaml")
        self.assertEqual(manifest["evaluation_date_utc"], "2025-08-20T00:00:00Z")
        self.assertEqual(manifest["governance_summary"]["artifact_total"], 24)
        self.assertEqual(manifest["governance_summary"]["review_blocking_count"], 5)
        self.assertEqual(manifest["governance_summary"]["overdue_review_count"], 5)
        self.assertEqual(manifest["governance_summary"]["escalation_required_count"], 6)
        self.assertEqual(manifest["governance_summary"]["awaiting_approval_count"], 1)
        self.assertEqual(manifest["governance_summary"]["waived_artifact_count"], 1)
        self.assertEqual(manifest["governance_summary"]["by_review_lifecycle_state"]["waived"], 1)
        self.assertEqual(manifest["governance_summary"]["by_provenance_assurance_level"]["reference_only"], 1)
        self.assertEqual(manifest["governance_summary"]["approval_expired_count"], 2)
        self.assertEqual(manifest["governance_summary"]["dual_review_pending_count"], 4)
        self.assertEqual(manifest["governance_summary"]["waiver_expiring_soon_count"], 1)
        self.assertEqual(manifest["reviewer_action_count"], 7)

        by_name = {item["architecture_subject"]: item for item in tracked}
        self.assertIn("Gateway Service", by_name)
        self.assertIn("Event Bus", by_name)
        self.assertNotIn("cbom", by_name["Event Bus"]["files"])
        self.assertEqual(by_name["Gateway Service"]["files"]["cbom"], "bom/cbom/gateway-service.cdx.json")
        self.assertEqual(by_name["Gateway Service"]["mapping_mode"], "one-to-many-evidence-subjects")
        self.assertEqual(by_name["Gateway Service"]["subject_kind"], "deployable-service")
        self.assertEqual(by_name["Gateway Service"]["owner"], "platform-team")
        self.assertEqual(by_name["Gateway Service"]["review_cadence"], "monthly")
        self.assertEqual(
            [item["evidence_subject_id"] for item in by_name["Gateway Service"]["evidence_subjects"]],
            ["gateway-runtime", "gateway-control-profile"],
        )
        self.assertEqual(
            [item["evidence_subject_id"] for item in by_name["Edge AI Runtime"]["evidence_subjects"]],
            ["edge-ai-runtime-service", "edge-ai-model-package"],
        )
        self.assertEqual(by_name["Gateway Service"]["artifacts"]["sbom"]["derived_maturity_state"], "evidence_backed")
        self.assertEqual(by_name["Gateway Service"]["artifacts"]["sbom"]["governed_maturity_state"], "partially_evidenced")
        self.assertEqual(by_name["Gateway Service"]["artifacts"]["sbom"]["freshness_state"], "fresh")
        self.assertEqual(by_name["Gateway Service"]["artifacts"]["sbom"]["review"]["review_status"], "approval-refresh-required")
        self.assertEqual(by_name["Gateway Service"]["artifacts"]["sbom"]["review"]["review_lifecycle_state"], "in_review")
        self.assertEqual(by_name["Gateway Service"]["artifacts"]["sbom"]["next_review_due"], "2025-07-10")
        self.assertEqual(by_name["Gateway Service"]["artifacts"]["sbom"]["review_due_status"], "overdue")
        self.assertEqual(by_name["Gateway Service"]["artifacts"]["sbom"]["reviewer_group"], "platform-engineering")
        self.assertEqual(by_name["Gateway Service"]["artifacts"]["sbom"]["approval_group"], "platform-security-review-board")
        self.assertTrue(by_name["Gateway Service"]["artifacts"]["sbom"]["approval_required"])
        self.assertTrue(by_name["Gateway Service"]["artifacts"]["sbom"]["awaiting_approval"])
        self.assertEqual(by_name["Gateway Service"]["artifacts"]["sbom"]["approval_state"], "expired")
        self.assertEqual(by_name["Gateway Service"]["artifacts"]["sbom"]["escalation_group"], "architecture-governance")
        self.assertTrue(by_name["Gateway Service"]["artifacts"]["sbom"]["escalation_required"])
        self.assertTrue(by_name["Gateway Service"]["artifacts"]["sbom"]["review_blocking"])
        self.assertEqual(
            by_name["Gateway Service"]["artifacts"]["sbom"]["selected_source"]["adapter"],
            "cyclonedx_json",
        )
        self.assertEqual(
            by_name["Gateway Service"]["artifacts"]["sbom"]["selected_source"]["reference"],
            "evidence/imports/gateway-runtime-imported-sbom.cdx.json",
        )
        self.assertEqual(by_name["Gateway Service"]["artifacts"]["cbom"]["derived_maturity_state"], "partially_evidenced")
        self.assertEqual(by_name["Gateway Service"]["artifacts"]["cbom"]["freshness_state"], "fresh")
        self.assertEqual(
            by_name["Gateway Service"]["artifacts"]["cbom"]["selected_source"]["evidence_subject_id"],
            "gateway-control-profile",
        )
        self.assertEqual(
            by_name["Gateway Service"]["artifacts"]["cbom"]["selected_source"]["evidence_kind"],
            "crypto_policy",
        )
        self.assertEqual(
            by_name["Gateway Service"]["artifacts"]["cbom"]["selected_source"]["reference"],
            "code/policy/edge-access-policy.rego",
        )
        self.assertEqual(by_name["API Gateway"]["owner"], "platform-edge-team")
        self.assertEqual(by_name["API Gateway"]["review_cadence"], "monthly")
        self.assertEqual(by_name["API Gateway"]["artifacts"]["vex"]["derived_maturity_state"], "partially_evidenced")
        self.assertEqual(by_name["API Gateway"]["artifacts"]["vex"]["governed_maturity_state"], "partially_evidenced")
        self.assertEqual(by_name["API Gateway"]["artifacts"]["vex"]["freshness_state"], "fresh")
        self.assertEqual(by_name["API Gateway"]["artifacts"]["vex"]["review"]["review_status"], "reviewed-with-open-followup")
        self.assertEqual(by_name["API Gateway"]["artifacts"]["vex"]["review"]["review_lifecycle_state"], "in_review")
        self.assertEqual(by_name["API Gateway"]["artifacts"]["vex"]["next_review_due"], "2025-09-11")
        self.assertEqual(by_name["API Gateway"]["artifacts"]["vex"]["selected_source"]["adapter"], "advisory_record")
        self.assertEqual(by_name["API Gateway"]["artifacts"]["vex"]["reviewer_group"], "vendor-assurance-and-product-security")
        self.assertEqual(by_name["API Gateway"]["artifacts"]["vex"]["approval_group"], "vendor-assurance-and-product-security")
        self.assertEqual(
            by_name["API Gateway"]["artifacts"]["vex"]["selected_source"]["reference"],
            "evidence/reviews/api-gateway-vendor-advisory-review.json",
        )
        self.assertEqual(by_name["Edge AI Runtime"]["provenance"]["derived_maturity_state"], "partially_evidenced")
        self.assertEqual(by_name["Edge AI Runtime"]["provenance"]["governed_maturity_state"], "partially_evidenced")
        self.assertEqual(by_name["Edge AI Runtime"]["provenance"]["freshness_state"], "expired")
        self.assertTrue(by_name["Edge AI Runtime"]["provenance"]["escalation_required"])
        self.assertEqual(by_name["Edge AI Runtime"]["provenance"]["escalation_status"], "expired-review-required")
        self.assertEqual(by_name["Edge AI Runtime"]["provenance"]["handoff_to"], "ai-assurance-board")
        self.assertEqual(by_name["Edge AI Runtime"]["provenance"]["reviewer_group"], "ai-assurance-and-ml-governance")
        self.assertEqual(by_name["Edge AI Runtime"]["provenance"]["approval_group"], "ai-assurance-board")
        self.assertEqual(by_name["Edge AI Runtime"]["provenance"]["review"]["review_status"], "reviewed-with-open-followup")
        self.assertEqual(by_name["Edge AI Runtime"]["provenance"]["review"]["review_lifecycle_state"], "in_review")
        self.assertEqual(by_name["Edge AI Runtime"]["provenance"]["approval_state"], "expired")
        self.assertTrue(by_name["Edge AI Runtime"]["provenance"]["dual_review_required"])
        self.assertFalse(by_name["Edge AI Runtime"]["provenance"]["dual_review_satisfied"])
        self.assertEqual(
            by_name["Edge AI Runtime"]["provenance"]["selected_source"]["provenance_attestation_type"],
            "reference_only",
        )
        self.assertEqual(
            by_name["Edge AI Runtime"]["provenance"]["selected_source"]["provenance_assurance_level"],
            "reference_only",
        )
        self.assertEqual(
            by_name["Edge AI Runtime"]["provenance"]["selected_source"]["reference"],
            "evidence/references/edge-ai-model-package-provenance-reference.json",
        )
        self.assertEqual(by_name["Identity Provider"]["artifacts"]["cbom"]["review"]["review_status"], "waived")
        self.assertEqual(by_name["Identity Provider"]["artifacts"]["cbom"]["review"]["review_lifecycle_state"], "waived")
        self.assertTrue(by_name["Identity Provider"]["artifacts"]["cbom"]["waiver_active"])
        self.assertEqual(by_name["Identity Provider"]["artifacts"]["cbom"]["waiver"]["waiver_owner"], "identity-security-board")
        self.assertEqual(by_name["Identity Provider"]["artifacts"]["cbom"]["waiver_expiry_state"], "expiring_soon")
        self.assertTrue(by_name["Identity Provider"]["artifacts"]["cbom"]["dual_review_required"])
        self.assertFalse(by_name["Identity Provider"]["artifacts"]["cbom"]["dual_review_satisfied"])
        self.assertEqual(by_name["Secrets Manager"]["artifacts"]["vex"]["derived_maturity_state"], "partially_evidenced")
        self.assertEqual(by_name["Secrets Manager"]["artifacts"]["vex"]["governed_maturity_state"], "partially_evidenced")
        self.assertEqual(by_name["Secrets Manager"]["artifacts"]["vex"]["freshness_state"], "expired")
        self.assertTrue(by_name["Secrets Manager"]["artifacts"]["vex"]["escalation_required"])
        self.assertEqual(by_name["Secrets Manager"]["artifacts"]["vex"]["handoff_to"], "trust-governance-board")
        self.assertEqual(by_name["Secrets Manager"]["artifacts"]["vex"]["reviewer_group"], "secrets-vendor-assurance")
        self.assertEqual(by_name["Secrets Manager"]["artifacts"]["vex"]["review"]["review_lifecycle_state"], "in_review")
        self.assertEqual(by_name["Gateway Service"]["artifacts"]["cbom"]["approval_state"], "current")
        self.assertTrue(by_name["Gateway Service"]["artifacts"]["cbom"]["dual_review_required"])
        self.assertFalse(by_name["Gateway Service"]["artifacts"]["cbom"]["dual_review_satisfied"])
        self.assertEqual(by_name["Event Bus"]["artifacts"]["cbom"]["derived_maturity_state"], "not_applicable")
        self.assertEqual(by_name["Event Bus"]["artifacts"]["cbom"]["freshness_state"], "not_applicable")

        coverage_csv = ROOT / "bom" / "coverage-matrix.csv"
        coverage_md = ROOT / "bom" / "coverage-matrix.md"
        evidence_csv = ROOT / "bom" / "evidence-matrix.csv"
        evidence_md = ROOT / "bom" / "evidence-matrix.md"
        governance_md = ROOT / "bom" / "governance-summary.md"
        reviewer_actions_md = ROOT / "bom" / "reviewer-actions.md"
        self.assertTrue(coverage_csv.exists())
        self.assertTrue(coverage_md.exists())
        self.assertTrue(evidence_csv.exists())
        self.assertTrue(evidence_md.exists())
        self.assertTrue(governance_md.exists())
        self.assertTrue(reviewer_actions_md.exists())
        with coverage_csv.open(newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), 6)
        gateway_row = next(row for row in rows if row["architecture_subject"] == "Gateway Service")
        self.assertEqual(gateway_row["subject_type"], "cyber-physical-runtime")
        self.assertEqual(gateway_row["owner"], "platform-team")
        self.assertEqual(gateway_row["review_cadence"], "monthly")
        self.assertEqual(gateway_row["sbom_reviewer_group"], "platform-engineering")
        self.assertEqual(gateway_row["sbom"], "partially_evidenced")
        self.assertEqual(gateway_row["cbom"], "partially_evidenced")
        api_gateway_row = next(row for row in rows if row["architecture_subject"] == "API Gateway")
        self.assertEqual(api_gateway_row["owner"], "platform-edge-team")
        self.assertEqual(api_gateway_row["vex"], "partially_evidenced")
        edge_ai_row = next(row for row in rows if row["architecture_subject"] == "Edge AI Runtime")
        self.assertEqual(edge_ai_row["owner"], "ai-team")
        event_bus_row = next(row for row in rows if row["architecture_subject"] == "Event Bus")
        self.assertEqual(event_bus_row["cbom"], "not_applicable")

        with evidence_csv.open(newline="") as handle:
            evidence_rows = list(csv.DictReader(handle))
        self.assertEqual(len(evidence_rows), 35)
        gateway_sbom_selected = next(
            row
            for row in evidence_rows
            if row["architecture_subject"] == "Gateway Service"
            and row["artifact_type"] == "sbom"
            and row["precedence_outcome"] == "selected"
            and row["evidence_subject"] == "gateway-runtime"
            and row["evidence_kind"] == "imported_artifact"
        )
        self.assertEqual(gateway_sbom_selected["binding_state"], "verified")
        self.assertEqual(gateway_sbom_selected["source_type"], "teaching-imported-cyclonedx")
        self.assertEqual(gateway_sbom_selected["adapter"], "cyclonedx_json")
        self.assertEqual(gateway_sbom_selected["input_state"], "local-file")
        self.assertEqual(gateway_sbom_selected["derived_maturity_state"], "evidence_backed")
        self.assertEqual(gateway_sbom_selected["governed_maturity_state"], "partially_evidenced")
        self.assertEqual(gateway_sbom_selected["freshness_state"], "fresh")
        self.assertEqual(gateway_sbom_selected["review_lifecycle_state"], "in_review")
        self.assertEqual(gateway_sbom_selected["review_status"], "approval-refresh-required")
        self.assertEqual(gateway_sbom_selected["approval_group"], "platform-security-review-board")
        self.assertEqual(gateway_sbom_selected["reviewer_group"], "platform-engineering")
        self.assertEqual(gateway_sbom_selected["next_review_due"], "2025-07-10")
        self.assertEqual(gateway_sbom_selected["review_due_status"], "overdue")
        self.assertEqual(gateway_sbom_selected["approval_required"], "true")
        self.assertEqual(gateway_sbom_selected["awaiting_approval"], "true")
        self.assertEqual(gateway_sbom_selected["approval_state"], "expired")
        self.assertEqual(gateway_sbom_selected["dual_review_required"], "false")
        self.assertEqual(gateway_sbom_selected["escalation_required"], "true")
        self.assertEqual(gateway_sbom_selected["review_blocking"], "true")
        self.assertEqual(gateway_sbom_selected["source_reference"], "evidence/imports/gateway-runtime-imported-sbom.cdx.json")
        gateway_cbom_selected = next(
            row
            for row in evidence_rows
            if row["architecture_subject"] == "Gateway Service"
            and row["artifact_type"] == "cbom"
            and row["precedence_outcome"] == "selected"
        )
        self.assertEqual(gateway_cbom_selected["binding_state"], "linked")
        self.assertEqual(gateway_cbom_selected["derived_maturity_state"], "partially_evidenced")
        self.assertEqual(gateway_cbom_selected["approval_state"], "current")
        self.assertEqual(gateway_cbom_selected["dual_review_required"], "true")
        self.assertEqual(gateway_cbom_selected["dual_review_satisfied"], "false")
        self.assertEqual(gateway_cbom_selected["escalation_status"], "dual-review-pending")
        self.assertEqual(gateway_cbom_selected["freshness_state"], "fresh")
        self.assertEqual(gateway_cbom_selected["evidence_subject"], "gateway-control-profile")
        self.assertEqual(gateway_cbom_selected["evidence_kind"], "crypto_policy")
        self.assertEqual(gateway_cbom_selected["source_reference"], "code/policy/edge-access-policy.rego")
        gateway_cbom_supporting = next(
            row
            for row in evidence_rows
            if row["architecture_subject"] == "Gateway Service"
            and row["artifact_type"] == "cbom"
            and row["precedence_outcome"] == "supporting"
            and row["evidence_kind"] == "repo_control_document"
        )
        self.assertEqual(gateway_cbom_supporting["source_reference"], "code/configs/gateway-security-baseline.yaml")
        edge_ai_model_provenance = next(
            row
            for row in evidence_rows
            if row["architecture_subject"] == "Edge AI Runtime"
            and row["evidence_subject"] == "edge-ai-model-package"
            and row["artifact_type"] == "provenance"
            and row["precedence_outcome"] == "selected"
        )
        self.assertEqual(edge_ai_model_provenance["subject_variant"], "model_package")
        self.assertEqual(edge_ai_model_provenance["binding_state"], "linked")
        self.assertEqual(edge_ai_model_provenance["precedence_outcome"], "selected")
        api_gateway_vex_selected = next(
            row
            for row in evidence_rows
            if row["architecture_subject"] == "API Gateway"
            and row["artifact_type"] == "vex"
            and row["precedence_outcome"] == "selected"
        )
        self.assertEqual(api_gateway_vex_selected["adapter"], "advisory_record")
        self.assertEqual(api_gateway_vex_selected["input_state"], "local-file")
        self.assertEqual(api_gateway_vex_selected["binding_state"], "linked")
        self.assertEqual(api_gateway_vex_selected["derived_maturity_state"], "partially_evidenced")
        self.assertEqual(api_gateway_vex_selected["governed_maturity_state"], "partially_evidenced")
        self.assertEqual(api_gateway_vex_selected["freshness_state"], "fresh")
        self.assertEqual(api_gateway_vex_selected["review_lifecycle_state"], "in_review")
        self.assertEqual(api_gateway_vex_selected["review_status"], "reviewed-with-open-followup")
        self.assertEqual(api_gateway_vex_selected["next_review_due"], "2025-09-11")
        self.assertEqual(api_gateway_vex_selected["escalation_required"], "false")
        self.assertEqual(api_gateway_vex_selected["source_reference"], "evidence/reviews/api-gateway-vendor-advisory-review.json")
        edge_ai_model_provenance = next(
            row
            for row in evidence_rows
            if row["architecture_subject"] == "Edge AI Runtime"
            and row["evidence_subject"] == "edge-ai-model-package"
            and row["artifact_type"] == "provenance"
            and row["precedence_outcome"] == "selected"
        )
        self.assertEqual(edge_ai_model_provenance["adapter"], "attestation_reference")
        self.assertEqual(edge_ai_model_provenance["input_state"], "local-file")
        self.assertEqual(edge_ai_model_provenance["binding_state"], "linked")
        self.assertEqual(edge_ai_model_provenance["derived_maturity_state"], "partially_evidenced")
        self.assertEqual(edge_ai_model_provenance["governed_maturity_state"], "partially_evidenced")
        self.assertEqual(edge_ai_model_provenance["freshness_state"], "expired")
        self.assertEqual(edge_ai_model_provenance["review_lifecycle_state"], "in_review")
        self.assertEqual(edge_ai_model_provenance["review_status"], "reviewed-with-open-followup")
        self.assertEqual(edge_ai_model_provenance["next_review_due"], "2025-07-15")
        self.assertEqual(edge_ai_model_provenance["review_due_status"], "overdue")
        self.assertEqual(edge_ai_model_provenance["escalation_required"], "true")
        self.assertEqual(edge_ai_model_provenance["escalation_status"], "expired-review-required")
        self.assertEqual(edge_ai_model_provenance["handoff_to"], "ai-assurance-board")
        self.assertEqual(edge_ai_model_provenance["reviewer_group"], "ai-assurance-and-ml-governance")
        self.assertEqual(edge_ai_model_provenance["provenance_attestation_type"], "reference_only")
        self.assertEqual(edge_ai_model_provenance["provenance_assurance_level"], "reference_only")
        self.assertEqual(edge_ai_model_provenance["approval_state"], "expired")
        self.assertEqual(edge_ai_model_provenance["dual_review_required"], "true")
        self.assertEqual(edge_ai_model_provenance["dual_review_satisfied"], "false")
        self.assertEqual(
            edge_ai_model_provenance["source_reference"],
            "evidence/references/edge-ai-model-package-provenance-reference.json",
        )
        identity_provider_cbom = next(
            row
            for row in evidence_rows
            if row["architecture_subject"] == "Identity Provider"
            and row["artifact_type"] == "cbom"
            and row["evidence_kind"] == "crypto_policy"
        )
        self.assertEqual(identity_provider_cbom["review_lifecycle_state"], "waived")
        self.assertEqual(identity_provider_cbom["waiver_state"], "active")
        self.assertEqual(identity_provider_cbom["waiver_active"], "true")
        self.assertEqual(identity_provider_cbom["waiver_expiry_state"], "expiring_soon")
        self.assertEqual(identity_provider_cbom["dual_review_required"], "true")
        self.assertEqual(identity_provider_cbom["dual_review_satisfied"], "false")
        self.assertEqual(identity_provider_cbom["waiver_owner"], "identity-security-board")
        self.assertEqual(identity_provider_cbom["escalation_required"], "false")
        secrets_manager_vex = next(
            row
            for row in evidence_rows
            if row["architecture_subject"] == "Secrets Manager"
            and row["artifact_type"] == "vex"
            and row["precedence_outcome"] == "selected"
        )
        self.assertEqual(secrets_manager_vex["adapter"], "advisory_record")
        self.assertEqual(secrets_manager_vex["input_state"], "local-file")
        self.assertEqual(secrets_manager_vex["derived_maturity_state"], "partially_evidenced")
        self.assertEqual(secrets_manager_vex["governed_maturity_state"], "partially_evidenced")
        self.assertEqual(secrets_manager_vex["freshness_state"], "expired")
        self.assertEqual(secrets_manager_vex["review_lifecycle_state"], "in_review")
        self.assertEqual(secrets_manager_vex["reviewer_group"], "secrets-vendor-assurance")
        self.assertEqual(secrets_manager_vex["handoff_to"], "trust-governance-board")
        self.assertEqual(secrets_manager_vex["source_reference"], "evidence/reviews/secrets-manager-vault-advisory-review.json")
        event_bus_cbom = next(
            row
            for row in evidence_rows
            if row["architecture_subject"] == "Event Bus"
            and row["artifact_type"] == "cbom"
        )
        self.assertEqual(event_bus_cbom["binding_state"], "not-applicable")
        self.assertEqual(event_bus_cbom["derived_maturity_state"], "not_applicable")

        gateway_sbom_doc = json.loads((ROOT / "bom" / "sbom" / "gateway-service.cdx.json").read_text())
        component_properties = {item["name"]: item["value"] for item in gateway_sbom_doc["metadata"]["component"]["properties"]}
        self.assertEqual(component_properties["smartparking.mapping_mode"], "one-to-many-evidence-subjects")
        self.assertEqual(component_properties["smartparking.owner"], "platform-team")
        self.assertEqual(component_properties["smartparking.review_cadence"], "monthly")
        self.assertEqual(component_properties["smartparking.selected_evidence_subject"], "gateway-runtime")
        self.assertEqual(component_properties["smartparking.selected_evidence_kind"], "imported_artifact")
        self.assertEqual(component_properties["smartparking.selected_evidence_adapter"], "cyclonedx_json")
        self.assertEqual(component_properties["smartparking.selected_evidence_input_state"], "local-file")
        self.assertEqual(component_properties["smartparking.selected_source_reference"], "evidence/imports/gateway-runtime-imported-sbom.cdx.json")
        self.assertEqual(component_properties["smartparking.derived_maturity_state"], "evidence_backed")
        self.assertEqual(component_properties["smartparking.governed_maturity_state"], "partially_evidenced")
        self.assertEqual(component_properties["smartparking.review_lifecycle_state"], "in_review")
        self.assertEqual(component_properties["smartparking.review_status"], "approval-refresh-required")
        self.assertEqual(component_properties["smartparking.approval_group"], "platform-security-review-board")
        self.assertEqual(component_properties["smartparking.reviewer_group"], "platform-engineering")
        self.assertEqual(component_properties["smartparking.escalation_group"], "architecture-governance")
        self.assertEqual(component_properties["smartparking.next_review_due"], "2025-07-10")
        self.assertEqual(component_properties["smartparking.review_due_status"], "overdue")
        self.assertEqual(component_properties["smartparking.approval_required"], "true")
        self.assertEqual(component_properties["smartparking.awaiting_approval"], "true")
        self.assertEqual(component_properties["smartparking.approval_state"], "expired")
        self.assertEqual(component_properties["smartparking.dual_review_required"], "false")
        self.assertEqual(component_properties["smartparking.escalation_required"], "true")
        self.assertEqual(component_properties["smartparking.review_blocking"], "true")
        self.assertEqual(component_properties["smartparking.provenance_maturity_state"], "scaffolded")
        gateway_cbom_doc = json.loads((ROOT / "bom" / "cbom" / "gateway-service.cdx.json").read_text())
        cbom_properties = {item["name"]: item["value"] for item in gateway_cbom_doc["metadata"]["component"]["properties"]}
        self.assertEqual(cbom_properties["smartparking.derived_maturity_state"], "partially_evidenced")
        self.assertEqual(cbom_properties["smartparking.freshness_state"], "fresh")
        self.assertEqual(cbom_properties["smartparking.selected_evidence_subject"], "gateway-control-profile")
        self.assertEqual(cbom_properties["smartparking.selected_evidence_kind"], "crypto_policy")
        self.assertEqual(cbom_properties["smartparking.selected_source_reference"], "code/policy/edge-access-policy.rego")
        api_gateway_vex_doc = json.loads((ROOT / "bom" / "vex" / "api-gateway.cdx.json").read_text())
        vex_properties = {item["name"]: item["value"] for item in api_gateway_vex_doc["metadata"]["component"]["properties"]}
        self.assertEqual(vex_properties["smartparking.owner"], "platform-edge-team")
        self.assertEqual(vex_properties["smartparking.review_cadence"], "monthly")
        self.assertEqual(vex_properties["smartparking.selected_evidence_adapter"], "advisory_record")
        self.assertEqual(vex_properties["smartparking.selected_evidence_input_state"], "local-file")
        self.assertEqual(vex_properties["smartparking.selected_source_reference"], "evidence/reviews/api-gateway-vendor-advisory-review.json")
        self.assertEqual(vex_properties["smartparking.derived_maturity_state"], "partially_evidenced")
        self.assertEqual(vex_properties["smartparking.governed_maturity_state"], "partially_evidenced")
        self.assertEqual(vex_properties["smartparking.review_lifecycle_state"], "in_review")
        self.assertEqual(vex_properties["smartparking.review_status"], "reviewed-with-open-followup")
        self.assertEqual(vex_properties["smartparking.next_review_due"], "2025-09-11")
        self.assertEqual(vex_properties["smartparking.escalation_required"], "false")
        self.assertEqual(vex_properties["smartparking.reviewer_group"], "vendor-assurance-and-product-security")

    def test_gate_demo_requires_secret(self) -> None:
        result = subprocess.run(
            ["python3", "code/secure_command_signing_demo.py"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SMART_PARKING_GATE_DEMO_SECRET", result.stderr + result.stdout)


if __name__ == "__main__":
    unittest.main()
