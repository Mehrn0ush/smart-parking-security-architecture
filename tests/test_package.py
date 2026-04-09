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
        self.assertEqual(manifest["schema_version"], "7.0")
        self.assertEqual(manifest["policy_file"], "model/supply-chain-mapping.yaml")
        self.assertEqual(manifest["evidence_file"], "model/supply-chain-evidence.yaml")
        self.assertEqual(manifest["evaluation_date_utc"], "2025-08-20T00:00:00Z")

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
        self.assertEqual(by_name["Gateway Service"]["artifacts"]["sbom"]["governed_maturity_state"], "evidence_backed")
        self.assertEqual(by_name["Gateway Service"]["artifacts"]["sbom"]["freshness_state"], "fresh")
        self.assertEqual(by_name["Gateway Service"]["artifacts"]["sbom"]["review"]["review_status"], "approved-for-teaching-use")
        self.assertEqual(by_name["Gateway Service"]["artifacts"]["sbom"]["next_review_due"], "2025-09-17")
        self.assertFalse(by_name["Gateway Service"]["artifacts"]["sbom"]["escalation_required"])
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
        self.assertEqual(by_name["API Gateway"]["artifacts"]["vex"]["next_review_due"], "2025-09-11")
        self.assertEqual(by_name["API Gateway"]["artifacts"]["vex"]["selected_source"]["adapter"], "advisory_record")
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
        self.assertEqual(by_name["Edge AI Runtime"]["provenance"]["review"]["review_status"], "reviewed-with-open-followup")
        self.assertEqual(
            by_name["Edge AI Runtime"]["provenance"]["selected_source"]["reference"],
            "evidence/references/edge-ai-model-package-provenance-reference.json",
        )
        self.assertEqual(by_name["Event Bus"]["artifacts"]["cbom"]["derived_maturity_state"], "not_applicable")
        self.assertEqual(by_name["Event Bus"]["artifacts"]["cbom"]["freshness_state"], "not_applicable")

        coverage_csv = ROOT / "bom" / "coverage-matrix.csv"
        coverage_md = ROOT / "bom" / "coverage-matrix.md"
        evidence_csv = ROOT / "bom" / "evidence-matrix.csv"
        evidence_md = ROOT / "bom" / "evidence-matrix.md"
        self.assertTrue(coverage_csv.exists())
        self.assertTrue(coverage_md.exists())
        self.assertTrue(evidence_csv.exists())
        self.assertTrue(evidence_md.exists())
        with coverage_csv.open(newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), 6)
        gateway_row = next(row for row in rows if row["architecture_subject"] == "Gateway Service")
        self.assertEqual(gateway_row["subject_type"], "cyber-physical-runtime")
        self.assertEqual(gateway_row["owner"], "platform-team")
        self.assertEqual(gateway_row["review_cadence"], "monthly")
        self.assertEqual(gateway_row["sbom"], "evidence_backed")
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
        self.assertEqual(gateway_sbom_selected["governed_maturity_state"], "evidence_backed")
        self.assertEqual(gateway_sbom_selected["freshness_state"], "fresh")
        self.assertEqual(gateway_sbom_selected["review_status"], "approved-for-teaching-use")
        self.assertEqual(gateway_sbom_selected["next_review_due"], "2025-09-17")
        self.assertEqual(gateway_sbom_selected["escalation_required"], "false")
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
        self.assertEqual(edge_ai_model_provenance["review_status"], "reviewed-with-open-followup")
        self.assertEqual(edge_ai_model_provenance["next_review_due"], "2025-07-15")
        self.assertEqual(edge_ai_model_provenance["escalation_required"], "true")
        self.assertEqual(edge_ai_model_provenance["escalation_status"], "expired-review-required")
        self.assertEqual(edge_ai_model_provenance["handoff_to"], "ai-assurance-board")
        self.assertEqual(
            edge_ai_model_provenance["source_reference"],
            "evidence/references/edge-ai-model-package-provenance-reference.json",
        )
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
        self.assertEqual(component_properties["smartparking.governed_maturity_state"], "evidence_backed")
        self.assertEqual(component_properties["smartparking.review_status"], "approved-for-teaching-use")
        self.assertEqual(component_properties["smartparking.next_review_due"], "2025-09-17")
        self.assertEqual(component_properties["smartparking.escalation_required"], "false")
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
        self.assertEqual(vex_properties["smartparking.review_status"], "reviewed-with-open-followup")
        self.assertEqual(vex_properties["smartparking.next_review_due"], "2025-09-11")
        self.assertEqual(vex_properties["smartparking.escalation_required"], "false")

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
