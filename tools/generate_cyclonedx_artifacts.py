#!/usr/bin/env python3
"""
Generate architecture-aware CycloneDX scaffolds from the packaged Structurizr model,
the supply-chain policy layer, and decomposed evidence subjects.

The repository remains architecture-first. This script only derives convenience
artifacts and reports from the authored model and the policy/evidence layers.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path


ARTIFACT_KINDS = ("sbom", "cbom", "vex")
ALL_EVIDENCE_ARTIFACTS = ("sbom", "cbom", "vex", "provenance")


def package_paths() -> dict[str, Path]:
    root = Path(__file__).resolve().parents[1]
    return {
        "root": root,
        "workspace_json": root / "model" / "workspace.json",
        "mapping": root / "model" / "supply-chain-mapping.yaml",
        "evidence": root / "model" / "supply-chain-evidence.yaml",
        "bom_root": root / "bom",
    }


def read_json(path: Path) -> dict:
    return json.loads(path.read_text())


def read_json_like_yaml(path: Path) -> dict:
    return json.loads(path.read_text())


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def json_bytes(value: object) -> bytes:
    return json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n"


def parse_timestamp(value: str) -> datetime | None:
    if not value or value == "not-verified":
        return None
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        try:
            parsed = datetime.fromisoformat(f"{value}T00:00:00+00:00")
        except ValueError:
            return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def is_placeholder_reference(reference: str) -> bool:
    return reference.startswith("placeholder://")


def is_external_reference(reference: str) -> bool:
    return "://" in reference and not is_placeholder_reference(reference)


def unique_join(values: list[str], default: str = "none") -> str:
    cleaned = sorted({value for value in values if value})
    return ", ".join(cleaned) if cleaned else default


def relative_to_root(path: Path, root: Path) -> str:
    return str(path.resolve().relative_to(root.resolve()))


def iter_elements(model: dict) -> list[dict]:
    elements = []
    elements.extend(model.get("people", []))
    for software_system in model.get("softwareSystems", []):
        elements.append(software_system)
        for container in software_system.get("containers", []):
            elements.append(container)
            elements.extend(container.get("components", []))
    return elements


def index_elements(model: dict) -> dict[str, dict]:
    return {element["id"]: element for element in iter_elements(model)}


def slug_from_arch_ref(arch_ref: str) -> str:
    return arch_ref.rsplit(".", 1)[-1]


def to_property_list(mapping: dict[str, object]) -> list[dict[str, str]]:
    properties = []
    for key, value in sorted(mapping.items()):
        rendered = str(value).lower() if isinstance(value, bool) else str(value)
        properties.append({"name": key, "value": rendered})
    return properties


def tracked_containers_by_arch_ref(workspace: dict) -> dict[str, dict]:
    tracked = {}
    for software_system in workspace["model"].get("softwareSystems", []):
        for container in software_system.get("containers", []):
            props = container.get("properties", {})
            arch_ref = props.get("arch.ref")
            if arch_ref and props.get("bom.enabled") == "true":
                tracked[arch_ref] = container
    return tracked


def relationship_summary(container: dict, elements_by_id: dict[str, dict]) -> list[dict[str, str]]:
    summary = []
    for relationship in container.get("relationships", []):
        destination = elements_by_id.get(relationship["destinationId"], {})
        summary.append(
            {
                "description": relationship.get("description", ""),
                "technology": relationship.get("technology", ""),
                "destination_name": destination.get("name", relationship["destinationId"]),
                "destination_tags": destination.get("tags", ""),
            }
        )
    return summary


def external_providers(container: dict, elements_by_id: dict[str, dict]) -> list[str]:
    providers = set()
    for relationship in container.get("relationships", []):
        destination = elements_by_id.get(relationship["destinationId"], {})
        if "external" in destination.get("tags", "").lower():
            providers.add(destination.get("name", relationship["destinationId"]))
    return sorted(providers)


def crypto_clues(container: dict, relationships: list[dict[str, str]]) -> list[str]:
    text_parts = [container.get("name", ""), container.get("description", ""), container.get("technology", ""), container.get("tags", "")]
    for relationship in relationships:
        text_parts.extend([relationship.get("description", ""), relationship.get("technology", ""), relationship.get("destination_name", "")])
    for component in container.get("components", []):
        text_parts.extend([component.get("name", ""), component.get("description", ""), component.get("technology", "")])
    combined = " ".join(text_parts).lower()
    clues = []
    if any(token in combined for token in ("mtls", "tls", "ssl")):
        clues.append("tls-or-mtls")
    if "vpn" in combined:
        clues.append("vpn-tunnel")
    if any(token in combined for token in ("x.509", "certificate", "vault")):
        clues.append("certificate-and-trust-material")
    if any(token in combined for token in ("oauth2", "oidc", "token", "keycloak", "auth0")):
        clues.append("token-issuance-and-validation")
    if any(token in combined for token in ("secret", "vault", "key management")):
        clues.append("key-and-secret-management")
    if any(token in combined for token in ("model versioning", "model registry", "onnx", "tensorflow lite")):
        clues.append("model-integrity-and-signing-surface")
    return clues or ["architecture-review-required"]


def normalize_policy_subject(container: dict, subject: dict, defaults: dict) -> dict:
    artifacts = {}
    for kind in ARTIFACT_KINDS:
        artifact = dict(subject["artifacts"].get(kind, {}))
        artifact.setdefault("applicable", False)
        artifact.setdefault("status", defaults["artifact_status"])
        artifact.setdefault("origin", defaults["artifact_origin"])
        if kind == "vex":
            artifact.setdefault("exploitability_context", defaults["vex_exploitability"])
        artifacts[kind] = artifact
    return {
        "mapping": subject,
        "container": container,
        "supplier": {
            "name": subject.get("supplier", {}).get("name", "Unspecified"),
            "type": subject.get("supplier", {}).get("type", defaults["supplier_type"]),
        },
        "mapping_mode": subject.get("mapping_mode", defaults["mapping_mode"]),
        "subject_type": subject.get("subject_type", defaults["subject_type"]),
        "subject_kind": subject.get("subject_kind", defaults["subject_kind"]),
        "ownership": subject.get("ownership", defaults["ownership"]),
        "owner": subject.get("owner", defaults["owner"]),
        "review_cadence": subject.get("review_cadence", defaults["review_cadence"]),
        "escalation_owner": subject.get("escalation_owner", defaults["escalation_owner"]),
        "domain_flags": subject.get("domain_flags", {}),
        "artifacts": artifacts,
    }


def validate_mapping(workspace: dict, mapping: dict) -> dict[str, dict]:
    tracked = tracked_containers_by_arch_ref(workspace)
    defaults = mapping["policy_defaults"]
    subjects = {}
    seen_bom_refs = set()
    seen_runtime_units = set()

    for subject in mapping["subjects"]:
        arch_ref = subject["arch_ref"]
        if arch_ref in subjects:
            raise SystemExit(f"Duplicate arch_ref in mapping: {arch_ref}")
        container = tracked.get(arch_ref)
        if not container:
            raise SystemExit(f"Mapping references unknown or untracked arch_ref: {arch_ref}")
        if subject["element_name"] != container["name"]:
            raise SystemExit(f"Mapping element_name mismatch for {arch_ref}: {subject['element_name']} != {container['name']}")
        props = container.get("properties", {})
        for key in ("arch.ref", "bom.ref", "runtime.unit", "deployment.zone", "asset.criticality"):
            if key not in props:
                raise SystemExit(f"Tracked container {container['name']} is missing DSL property {key}")
        if props["bom.ref"] != subject["bom_ref"]:
            raise SystemExit(f"bom.ref mismatch for {arch_ref}")
        if props["runtime.unit"] != subject["runtime_unit"]:
            raise SystemExit(f"runtime.unit mismatch for {arch_ref}")
        if "Supply Chain Tracked" not in container.get("tags", ""):
            raise SystemExit(f"Tracked container {container['name']} is missing the Supply Chain Tracked tag")
        if subject["bom_ref"] in seen_bom_refs:
            raise SystemExit(f"Duplicate bom_ref in mapping: {subject['bom_ref']}")
        seen_bom_refs.add(subject["bom_ref"])
        if subject["runtime_unit"] in seen_runtime_units:
            raise SystemExit(f"Duplicate runtime_unit in mapping: {subject['runtime_unit']}")
        seen_runtime_units.add(subject["runtime_unit"])
        subjects[arch_ref] = normalize_policy_subject(container, subject, defaults)

    missing = sorted(set(tracked) - set(subjects))
    if missing:
        raise SystemExit(f"Tracked DSL containers missing from supply-chain mapping: {missing}")
    return dict(sorted(subjects.items(), key=lambda item: item[1]["mapping"]["element_name"]))


def normalize_review(review: dict | None, defaults: dict) -> dict:
    review = dict(review or {})
    return {
        "review_status": review.get("review_status", defaults["review_status"]),
        "last_reviewed": review.get("last_reviewed", defaults["last_reviewed"]),
        "reviewed_by": review.get("reviewed_by", defaults["reviewed_by"]),
        "review_notes": review.get("review_notes", defaults["review_notes"]),
        "next_review_due": review.get("next_review_due", defaults["next_review_due"]),
    }


def normalize_cyclonedx_input(payload: dict) -> dict:
    if payload.get("bomFormat") != "CycloneDX":
        raise SystemExit("CycloneDX adapter expected bomFormat=CycloneDX.")
    component = payload.get("metadata", {}).get("component", {})
    return {
        "adapter": "cyclonedx_json",
        "format": payload.get("specVersion", "unknown"),
        "component_name": component.get("name", "unknown"),
        "component_version": component.get("version", "unknown"),
        "component_count": len(payload.get("components", [])),
    }


def normalize_package_manifest_input(text: str, reference: str) -> dict:
    if reference.endswith(".json"):
        payload = json.loads(text)
        if isinstance(payload, dict):
            entries = payload.get("packages", [])
        elif isinstance(payload, list):
            entries = payload
        else:
            entries = []
    else:
        entries = [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]
    return {
        "adapter": "package_manifest",
        "entry_count": len(entries),
    }


def normalize_advisory_record_input(payload: dict) -> dict:
    if payload.get("record_type") not in {"vendor_advisory_review", "advisory_review"}:
        raise SystemExit("Advisory record adapter expected record_type vendor_advisory_review or advisory_review.")
    return {
        "adapter": "advisory_record",
        "subject": payload.get("subject", "unknown"),
        "review_outcome": payload.get("review_outcome", "unspecified"),
        "reviewed_at": payload.get("reviewed_at", "unknown"),
        "review_status": payload.get("review_status", "unknown"),
    }


def normalize_attestation_reference_input(payload: dict) -> dict:
    if payload.get("record_type") not in {"teaching_provenance_reference", "attestation_reference"}:
        raise SystemExit("Attestation reference adapter expected record_type teaching_provenance_reference or attestation_reference.")
    return {
        "adapter": "attestation_reference",
        "record_type": payload.get("record_type", "unknown"),
        "subject": payload.get("subject", "unknown"),
        "statement_type": payload.get("statement_type", payload.get("predicateType", "reference")),
    }


def load_adapter_metadata(adapter: str, path: Path) -> dict:
    raw_text = path.read_text()
    if adapter == "cyclonedx_json":
        return normalize_cyclonedx_input(json.loads(raw_text))
    if adapter == "package_manifest":
        return normalize_package_manifest_input(raw_text, str(path))
    if adapter == "advisory_record":
        return normalize_advisory_record_input(json.loads(raw_text))
    if adapter == "attestation_reference":
        return normalize_attestation_reference_input(json.loads(raw_text))
    raise SystemExit(f"Unsupported evidence adapter: {adapter}")


def normalize_source(source: dict, defaults: dict, package_root: Path) -> dict:
    normalized = dict(source)
    normalized.setdefault("evidence_kind", "repo_control_document")
    normalized.setdefault("collection_method", defaults["collection_method"])
    normalized.setdefault("maturity", defaults["maturity"])
    normalized.setdefault("confidence", defaults["confidence"])
    normalized.setdefault("last_verified", defaults["last_verified"])
    normalized.setdefault("limitations", defaults["limitations"])
    normalized.setdefault("adapter", defaults["adapter"])
    if "source_type" not in normalized or "reference" not in normalized:
        raise SystemExit("Each evidence source must include source_type and reference.")
    reference = normalized["reference"]
    if is_placeholder_reference(reference):
        normalized["input_state"] = "placeholder"
        normalized["input_summary"] = None
        normalized["source_sha256"] = "none"
        return normalized
    if is_external_reference(reference):
        normalized["input_state"] = "external-reference"
        normalized["input_summary"] = None
        normalized["source_sha256"] = "none"
        return normalized
    path = (package_root / reference).resolve()
    if normalized["adapter"] != "none":
        normalized["input_summary"] = load_adapter_metadata(normalized["adapter"], path)
    else:
        normalized["input_summary"] = None
    normalized["input_state"] = "local-file"
    normalized["source_sha256"] = sha256_file(path)
    return normalized


def normalize_artifact_evidence(kind: str, artifact: dict, defaults: dict, applicable: bool, package_root: Path, subject_review: dict) -> dict:
    normalized = dict(artifact or {})
    review = normalize_review(normalized.pop("review", None), defaults if subject_review is None else {**defaults, **subject_review})
    normalized.setdefault("content_status", defaults["content_status"] if applicable else "not-applicable")
    normalized.setdefault("binding_state", defaults["binding_state"] if applicable else "not-applicable")
    normalized.setdefault("evidence_scope", defaults["evidence_scope"] if applicable else "none")
    normalized["sources"] = [normalize_source(source, defaults, package_root) for source in normalized.get("sources", [])]
    normalized["review"] = review
    if not applicable and normalized["sources"]:
        raise SystemExit(f"Non-applicable artifact kind {kind} must not define evidence sources.")
    return normalized


def validate_evidence(mapping_subjects: dict[str, dict], evidence: dict, package_root: Path) -> dict[str, list[dict]]:
    defaults = evidence["defaults"]
    normalized = {}
    seen_ids = set()

    for subject in evidence["subjects"]:
        arch_ref = subject["arch_ref"]
        if arch_ref not in mapping_subjects:
            raise SystemExit(f"Evidence references unknown tracked subject: {arch_ref}")
        mapping_subject = mapping_subjects[arch_ref]
        mapping_data = mapping_subject["mapping"]
        if subject.get("bom_ref", mapping_data["bom_ref"]) != mapping_data["bom_ref"]:
            raise SystemExit(f"Evidence bom_ref mismatch for {arch_ref}")
        if subject.get("runtime_unit", mapping_data["runtime_unit"]) != mapping_data["runtime_unit"]:
            raise SystemExit(f"Evidence runtime_unit mismatch for {arch_ref}")

        evidence_subjects = []
        for item in subject.get("evidence_subjects", []):
            evidence_subject_id = item["evidence_subject_id"]
            if evidence_subject_id in seen_ids:
                raise SystemExit(f"Duplicate evidence_subject_id: {evidence_subject_id}")
            seen_ids.add(evidence_subject_id)
            subject_review = normalize_review(item.get("review"), defaults)
            artifact_evidence = {}
            for kind in ALL_EVIDENCE_ARTIFACTS:
                applicable = True if kind == "provenance" else mapping_subject["artifacts"][kind]["applicable"]
                artifact = normalize_artifact_evidence(
                    kind,
                    item.get("artifact_evidence", {}).get(kind, {}),
                    defaults,
                    applicable,
                    package_root,
                    subject_review,
                )
                for source in artifact["sources"]:
                    reference = source["reference"]
                    if not is_placeholder_reference(reference) and not is_external_reference(reference):
                        target = (package_root / reference).resolve()
                        if not target.exists():
                            raise SystemExit(f"Evidence reference does not exist for {evidence_subject_id}: {reference}")
                        if not str(target).startswith(str(package_root.resolve())):
                            raise SystemExit(f"Evidence reference escapes the package for {evidence_subject_id}: {reference}")
                artifact_evidence[kind] = artifact
            evidence_subjects.append(
                {
                    "evidence_subject_id": evidence_subject_id,
                    "subject_variant": item.get("subject_variant", "primary"),
                    "subject_kind": item.get("subject_kind", mapping_subject["subject_kind"]),
                    "runtime_unit": item.get("runtime_unit", mapping_data["runtime_unit"]),
                    "review": subject_review,
                    "artifact_evidence": artifact_evidence,
                }
            )
        if not evidence_subjects:
            raise SystemExit(f"Evidence subject {arch_ref} must define at least one evidence_subject.")
        normalized[arch_ref] = evidence_subjects

    missing = sorted(set(mapping_subjects) - set(normalized))
    if missing:
        raise SystemExit(f"Tracked policy subjects missing evidence bindings: {missing}")
    return normalized


def evidence_summary(sources: list[dict], artifact_evidence: dict) -> dict[str, object]:
    return {
        "content_status": artifact_evidence["content_status"],
        "binding_state": artifact_evidence["binding_state"],
        "evidence_scope": artifact_evidence["evidence_scope"],
        "source_count": len(sources),
        "evidence_kinds": unique_join([source["evidence_kind"] for source in sources]),
        "source_types": unique_join([source["source_type"] for source in sources]),
        "collection_methods": unique_join([source["collection_method"] for source in sources], default="none"),
        "maturity": unique_join([source["maturity"] for source in sources], default="planned"),
        "confidence": unique_join([source["confidence"] for source in sources], default="low"),
        "last_verified": unique_join([source["last_verified"] for source in sources], default="not-verified"),
        "limitations": unique_join([source["limitations"] for source in sources], default="none-documented"),
        "references": [source["reference"] for source in sources],
    }


def admissible_source(source: dict, artifact_evidence: dict, rule: dict) -> bool:
    if artifact_evidence["binding_state"] not in rule.get("allowed_binding_states", []):
        return False
    allowed_kinds = rule.get("allowed_evidence_kinds")
    if allowed_kinds and source["evidence_kind"] not in allowed_kinds:
        return False
    allowed_methods = rule.get("allowed_collection_methods")
    if allowed_methods and source["collection_method"] not in allowed_methods:
        return False
    required_methods = rule.get("required_collection_methods")
    if required_methods and source["collection_method"] not in required_methods:
        return False
    if rule.get("require_last_verified") and not parse_timestamp(source.get("last_verified", "")):
        return False
    if not rule.get("allow_placeholder_references", True) and is_placeholder_reference(source["reference"]):
        return False
    return True


def evidence_kind_rank(source: dict, precedence: list[str]) -> int:
    if source["evidence_kind"] in precedence:
        return precedence.index(source["evidence_kind"])
    return len(precedence)


def collection_method_rank(source: dict) -> int:
    order = ["scanner_derived", "imported", "advisory_reviewed", "manually_curated"]
    return order.index(source["collection_method"]) if source["collection_method"] in order else len(order)


def choose_best_source(candidates: list[dict], precedence: list[str]) -> dict | None:
    if not candidates:
        return None
    return sorted(
        candidates,
        key=lambda source: (
            evidence_kind_rank(source, precedence),
            collection_method_rank(source),
            source["evidence_subject_id"],
            source["source_type"],
            source["reference"],
        ),
    )[0]


def compute_freshness(selected_source: dict | None, artifact_kind: str, artifact_rules: dict, evaluation_time: datetime, not_applicable: bool) -> str:
    if not_applicable:
        return "not_applicable"
    if not selected_source:
        return "unknown"
    verified_at = parse_timestamp(selected_source.get("last_verified", ""))
    if not verified_at:
        return "unknown"
    thresholds = artifact_rules.get(artifact_kind, {}).get("freshness_days", {})
    fresh_days = thresholds.get("fresh", 30)
    stale_days = thresholds.get("stale", 90)
    age_days = (evaluation_time - verified_at).days
    if age_days <= fresh_days:
        return "fresh"
    if age_days <= stale_days:
        return "stale"
    return "expired"


def cadence_days(subject: dict, cadence: str) -> int | None:
    return subject.get("review_cadence_days", {}).get(cadence)


def compute_next_review_due(review: dict, subject: dict, selected_source: dict | None) -> str:
    explicit = review.get("next_review_due", "auto")
    if explicit not in {"", "auto"}:
        return explicit
    cadence = cadence_days(subject, subject["review_cadence"])
    if not cadence:
        return "unscheduled"
    base = parse_timestamp(review.get("last_reviewed", ""))
    if not base and selected_source:
        base = parse_timestamp(selected_source.get("last_verified", ""))
    if not base:
        return "unscheduled"
    due = base + timedelta(days=cadence)
    return due.date().isoformat()


def derive_review_governance(subject: dict, artifact_kind: str, artifact_rules: dict, state: dict, review: dict, selected_source: dict | None) -> dict:
    rule = artifact_rules.get(artifact_kind, {}).get("review_governance", {})
    freshness = state["freshness_state"]
    escalation_required = False
    escalation_status = "not-required"
    if freshness == "stale" and rule.get("stale_requires_escalation", False):
        escalation_required = True
        escalation_status = "stale-review-required"
    if freshness == "expired" and rule.get("expired_requires_escalation", False):
        escalation_required = True
        escalation_status = "expired-review-required"
    review_blocking = freshness == "expired" and rule.get("expired_blocks_evidence_backed", False) and state["maturity_state"] == "evidence_backed"
    governed_maturity_state = "partially_evidenced" if review_blocking else state["maturity_state"]
    handoff_to = subject.get("escalation_owner", subject["owner"]) if escalation_required else "none"
    return {
        "review": review,
        "next_review_due": compute_next_review_due(review, subject, selected_source),
        "escalation_required": escalation_required,
        "escalation_owner": subject.get("escalation_owner", subject["owner"]),
        "handoff_to": handoff_to,
        "escalation_status": escalation_status,
        "review_blocking": review_blocking,
        "governed_maturity_state": governed_maturity_state,
    }


def aggregate_artifact(subject: dict, artifact_kind: str, artifact_rules: dict, evaluation_time: datetime) -> dict:
    artifact_policy = subject["artifacts"].get(artifact_kind, {"applicable": True, "status": "n/a", "origin": "n/a"})
    evidence_subjects = subject["evidence_subjects"]
    evidence_entries = []
    all_sources = []
    for evidence_subject in evidence_subjects:
        artifact_evidence = evidence_subject["artifact_evidence"][artifact_kind]
        sources = []
        for source in artifact_evidence["sources"]:
            enriched = dict(source)
            enriched["evidence_subject_id"] = evidence_subject["evidence_subject_id"]
            enriched["subject_variant"] = evidence_subject["subject_variant"]
            sources.append(enriched)
            all_sources.append(enriched)
        evidence_entries.append(
            {
                "evidence_subject_id": evidence_subject["evidence_subject_id"],
                "subject_variant": evidence_subject["subject_variant"],
                "subject_kind": evidence_subject["subject_kind"],
                "runtime_unit": evidence_subject["runtime_unit"],
                "subject_review": evidence_subject["review"],
                "artifact_evidence": artifact_evidence,
                "sources": sources,
            }
        )

    not_applicable = artifact_kind != "provenance" and not artifact_policy["applicable"]
    if not_applicable:
        representative_review = evidence_entries[0]["artifact_evidence"]["review"] if evidence_entries else {
            "review_status": "not-applicable",
            "last_reviewed": "not-reviewed",
            "reviewed_by": "unassigned",
            "review_notes": "Artifact not applicable.",
            "next_review_due": "none",
        }
        return {
            "policy": artifact_policy,
            "evidence_entries": evidence_entries,
            "summary": evidence_summary([], {"content_status": "not-applicable", "binding_state": "not-applicable", "evidence_scope": "none"}),
            "partial_candidates": [],
            "backed_candidates": [],
            "selected_source": None,
            "maturity_state": "not_applicable",
            "freshness_state": "not_applicable",
            "governance": {
                "review": representative_review,
                "next_review_due": "none",
                "escalation_required": False,
                "escalation_owner": subject.get("escalation_owner", subject["owner"]),
                "handoff_to": "none",
                "escalation_status": "not-applicable",
                "review_blocking": False,
                "governed_maturity_state": "not_applicable",
            },
        }

    partial_rule = artifact_rules.get(artifact_kind, {}).get("partial", {})
    backed_rule = artifact_rules.get(artifact_kind, {}).get("evidence_backed", {})
    precedence = artifact_rules.get(artifact_kind, {}).get("precedence", [])
    partial_candidates = []
    backed_candidates = []

    for entry in evidence_entries:
        artifact_evidence = entry["artifact_evidence"]
        for source in entry["sources"]:
            if admissible_source(source, artifact_evidence, partial_rule):
                partial_candidates.append(source)
            if admissible_source(source, artifact_evidence, backed_rule):
                backed_candidates.append(source)

    selected_source = choose_best_source(backed_candidates, precedence)
    maturity_state = "evidence_backed" if selected_source else "scaffolded"
    if not selected_source:
        selected_source = choose_best_source(partial_candidates, precedence)
        if selected_source:
            maturity_state = "partially_evidenced"

    freshness_state = compute_freshness(selected_source, artifact_kind, artifact_rules, evaluation_time, False)

    # Summary over every evidence subject entry for visibility, not only selected candidates.
    combined_sources = all_sources
    representative_evidence = evidence_entries[0]["artifact_evidence"] if evidence_entries else {
        "content_status": "scaffolded",
        "binding_state": "planned",
        "evidence_scope": "runtime-unit",
    }
    summary = evidence_summary(combined_sources, representative_evidence)
    if maturity_state == "evidence_backed":
        summary["content_status"] = "evidence-backed"
    elif maturity_state == "partially_evidenced":
        summary["content_status"] = "partially-evidenced"
    elif maturity_state == "not_applicable":
        summary["content_status"] = "not-applicable"
    else:
        summary["content_status"] = representative_evidence["content_status"]

    selected_entry = None
    if selected_source:
        selected_entry = next((entry for entry in evidence_entries if entry["evidence_subject_id"] == selected_source["evidence_subject_id"]), None)
    effective_review = selected_entry["artifact_evidence"]["review"] if selected_entry else representative_evidence["review"]
    governance = derive_review_governance(
        subject,
        artifact_kind,
        artifact_rules,
        {"maturity_state": maturity_state, "freshness_state": freshness_state},
        effective_review,
        selected_source,
    )

    return {
        "policy": artifact_policy,
        "evidence_entries": evidence_entries,
        "summary": summary,
        "partial_candidates": partial_candidates,
        "backed_candidates": backed_candidates,
        "selected_source": selected_source,
        "maturity_state": maturity_state,
        "freshness_state": freshness_state,
        "governance": governance,
    }


def build_subject_states(subject: dict, artifact_rules: dict, evaluation_time: datetime) -> dict:
    states = {}
    for artifact_kind in ALL_EVIDENCE_ARTIFACTS:
        states[artifact_kind] = aggregate_artifact(subject, artifact_kind, artifact_rules, evaluation_time)
    return states


def base_component(subject: dict, artifact_kind: str) -> dict:
    container = subject["container"]
    props = container["properties"]
    mapping = subject["mapping"]
    policy_artifact = subject["artifacts"][artifact_kind]
    state = subject["artifact_states"][artifact_kind]
    summary = state["summary"]
    selected = state["selected_source"]
    provenance_state = subject["artifact_states"]["provenance"]
    provenance_selected = provenance_state["selected_source"]

    component = {
        "bom-ref": f"{mapping['bom_ref']}:{artifact_kind}",
        "type": "application",
        "group": "smartparking",
        "name": container["name"],
        "version": "0.5.0-architecture-scaffold",
        "description": container.get("description", ""),
        "properties": to_property_list(
            {
                "smartparking.arch_ref": props["arch.ref"],
                "smartparking.bom_ref": mapping["bom_ref"],
                "smartparking.runtime_unit": mapping["runtime_unit"],
                "smartparking.mapping_mode": subject["mapping_mode"],
                "smartparking.subject_type": subject["subject_type"],
                "smartparking.subject_kind": subject["subject_kind"],
                "smartparking.ownership": subject["ownership"],
                "smartparking.owner": subject["owner"],
                "smartparking.review_cadence": subject["review_cadence"],
                "smartparking.escalation_owner_subject": subject["escalation_owner"],
                "smartparking.deployment_zone": props["deployment.zone"],
                "smartparking.asset_criticality": props["asset.criticality"],
                "smartparking.supplier_type": subject["supplier"]["type"],
                "smartparking.supplier_name": subject["supplier"]["name"],
                "smartparking.artifact_kind": artifact_kind,
                "smartparking.artifact_origin": policy_artifact["origin"],
                "smartparking.artifact_status": policy_artifact["status"],
                "smartparking.derived_maturity_state": state["maturity_state"],
                "smartparking.governed_maturity_state": state["governance"]["governed_maturity_state"],
                "smartparking.freshness_state": state["freshness_state"],
                "smartparking.review_status": state["governance"]["review"]["review_status"],
                "smartparking.last_reviewed": state["governance"]["review"]["last_reviewed"],
                "smartparking.reviewed_by": state["governance"]["review"]["reviewed_by"],
                "smartparking.next_review_due": state["governance"]["next_review_due"],
                "smartparking.escalation_required": state["governance"]["escalation_required"],
                "smartparking.escalation_status": state["governance"]["escalation_status"],
                "smartparking.escalation_owner": state["governance"]["escalation_owner"],
                "smartparking.handoff_to": state["governance"]["handoff_to"],
                "smartparking.review_blocking": state["governance"]["review_blocking"],
                "smartparking.evidence_reference_count": summary["source_count"],
                "smartparking.evidence_kinds": summary["evidence_kinds"],
                "smartparking.evidence_source_types": summary["source_types"],
                "smartparking.selected_evidence_subject": selected["evidence_subject_id"] if selected else "none",
                "smartparking.selected_evidence_kind": selected["evidence_kind"] if selected else "none",
                "smartparking.selected_evidence_adapter": selected["adapter"] if selected else "none",
                "smartparking.selected_evidence_input_state": selected["input_state"] if selected else "none",
                "smartparking.selected_source_type": selected["source_type"] if selected else "none",
                "smartparking.selected_source_reference": selected["reference"] if selected else "none",
                "smartparking.provenance_maturity_state": provenance_state["maturity_state"],
                "smartparking.provenance_freshness_state": provenance_state["freshness_state"],
                "smartparking.provenance_selected_source": provenance_selected["source_type"] if provenance_selected else "none",
                "smartparking.synthetic_content": state["maturity_state"] == "scaffolded",
                "smartparking.technology": container.get("technology", ""),
                "smartparking.physical_control": subject["domain_flags"].get("physical_control", "unspecified"),
                "smartparking.safety_impact": subject["domain_flags"].get("safety_impact", "unspecified"),
                "smartparking.ai_decision_role": subject["domain_flags"].get("ai_decision_role", "none"),
                "smartparking.internet_exposure": subject["domain_flags"].get("internet_exposure", "unspecified"),
                "smartparking.privilege_level": subject["domain_flags"].get("privilege_level", "unspecified"),
                "smartparking.handles_secrets": subject["domain_flags"].get("handles_secrets", False),
                "smartparking.cyber_physical_criticality": subject["domain_flags"].get("cyber_physical_criticality", "unspecified"),
            }
        ),
    }
    if container.get("url"):
        component["externalReferences"] = [{"type": "website", "url": container["url"]}]
    return component


def sbom_document(subject: dict, relationships: list[dict[str, str]], providers: list[str]) -> dict:
    container = subject["container"]
    state = subject["artifact_states"]["sbom"]
    component = base_component(subject, "sbom")
    component["properties"].extend(
        to_property_list(
            {
                "smartparking.sbom_scope": container["properties"]["sbom.scope"],
                "smartparking.relationship_count": len(relationships),
                "smartparking.external_provider_count": len(providers),
            }
        )
    )
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, component['bom-ref'])}",
        "version": 1,
        "metadata": {
            "component": component,
            "properties": to_property_list(
                {
                    "smartparking.scope_kind": "sbom",
                    "smartparking.evidence_mode": "synthetic-with-rule-evaluated-bindings",
                    "smartparking.external_providers": ", ".join(providers) if providers else "none-modeled",
                    "smartparking.evidence_references": unique_join(state["summary"]["references"], default="none-linked"),
                    "smartparking.evidence_limitations": state["summary"]["limitations"],
                    "smartparking.note": "Architecture-derived scaffold only. Replace with scanner-backed inventory for production use.",
                }
            ),
        },
        "components": [],
        "dependencies": [{"ref": component["bom-ref"], "dependsOn": []}],
    }


def cbom_document(subject: dict, relationships: list[dict[str, str]]) -> dict:
    container = subject["container"]
    state = subject["artifact_states"]["cbom"]
    component = base_component(subject, "cbom")
    component["properties"].extend(
        to_property_list(
            {
                "smartparking.cbom_scope": container["properties"]["cbom.scope"],
                "smartparking.crypto_controls": ", ".join(crypto_clues(container, relationships)),
            }
        )
    )
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, component['bom-ref'])}",
        "version": 1,
        "metadata": {
            "component": component,
            "properties": to_property_list(
                {
                    "smartparking.scope_kind": "cbom",
                    "smartparking.evidence_mode": "synthetic-with-rule-evaluated-bindings",
                    "smartparking.evidence_references": unique_join(state["summary"]["references"], default="none-linked"),
                    "smartparking.evidence_limitations": state["summary"]["limitations"],
                    "smartparking.note": "Architecture-derived CBOM scaffold. It inventories cryptographic scope and expected controls, not discovered key material.",
                }
            ),
        },
        "components": [],
        "dependencies": [{"ref": component["bom-ref"], "dependsOn": []}],
    }


def vex_document(subject: dict, relationships: list[dict[str, str]]) -> dict:
    container = subject["container"]
    state = subject["artifact_states"]["vex"]
    component = base_component(subject, "vex")
    component["properties"].extend(
        to_property_list(
            {
                "smartparking.vex_scope": container["properties"]["vex.scope"],
                "smartparking.relationship_count": len(relationships),
                "smartparking.exploitability_context": subject["artifacts"]["vex"]["exploitability_context"],
            }
        )
    )
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, component['bom-ref'])}",
        "version": 1,
        "metadata": {
            "component": component,
            "properties": to_property_list(
                {
                    "smartparking.scope_kind": "vex",
                    "smartparking.default_analysis_state": "not-reviewed",
                    "smartparking.evidence_mode": "synthetic-with-rule-evaluated-bindings",
                    "smartparking.evidence_references": unique_join(state["summary"]["references"], default="none-linked"),
                    "smartparking.evidence_limitations": state["summary"]["limitations"],
                    "smartparking.note": "Architecture-derived VEX scaffold. Add real vulnerability assertions only after scanner or advisory review.",
                }
            ),
        },
        "vulnerabilities": [],
    }


def build_coverage_rows(subjects: list[dict]) -> list[dict[str, str]]:
    rows = []
    for subject in subjects:
        container = subject["container"]
        props = container["properties"]
        rows.append(
            {
                "architecture_subject": subject["mapping"]["element_name"],
                "runtime_unit": subject["mapping"]["runtime_unit"],
                "deployment_zone": props["deployment.zone"],
                "criticality": props["asset.criticality"],
                "subject_type": subject["subject_type"],
                "owner": subject["owner"],
                "review_cadence": subject["review_cadence"],
                "sbom": subject["artifact_states"]["sbom"]["governance"]["governed_maturity_state"],
                "cbom": subject["artifact_states"]["cbom"]["governance"]["governed_maturity_state"] if subject["artifacts"]["cbom"]["applicable"] else "not_applicable",
                "vex": subject["artifact_states"]["vex"]["governance"]["governed_maturity_state"],
                "generated_files": "; ".join(
                    filter(
                        None,
                        [
                            f"bom/sbom/{slug_from_arch_ref(props['arch.ref'])}.cdx.json",
                            f"bom/cbom/{slug_from_arch_ref(props['arch.ref'])}.cdx.json" if subject["artifacts"]["cbom"]["applicable"] else "",
                            f"bom/vex/{slug_from_arch_ref(props['arch.ref'])}.cdx.json",
                        ],
                    )
                ),
            }
        )
    return rows


def build_evidence_rows(subjects: list[dict]) -> list[dict[str, str]]:
    rows = []
    for subject in subjects:
        for artifact_kind in ALL_EVIDENCE_ARTIFACTS:
            state = subject["artifact_states"][artifact_kind]
            selected = state["selected_source"]
            for entry in state["evidence_entries"]:
                artifact_evidence = entry["artifact_evidence"]
                if not entry["sources"]:
                    rows.append(
                        {
                            "architecture_subject": subject["mapping"]["element_name"],
                            "evidence_subject": entry["evidence_subject_id"],
                            "subject_variant": entry["subject_variant"],
                            "runtime_unit": entry["runtime_unit"],
                            "owner": subject["owner"],
                            "review_cadence": subject["review_cadence"],
                            "review_status": artifact_evidence["review"]["review_status"],
                            "last_reviewed": artifact_evidence["review"]["last_reviewed"],
                            "reviewed_by": artifact_evidence["review"]["reviewed_by"],
                            "review_notes": artifact_evidence["review"]["review_notes"],
                            "next_review_due": state["governance"]["next_review_due"],
                            "escalation_required": str(state["governance"]["escalation_required"]).lower(),
                            "escalation_status": state["governance"]["escalation_status"],
                            "handoff_to": state["governance"]["handoff_to"],
                            "review_blocking": str(state["governance"]["review_blocking"]).lower(),
                            "artifact_type": artifact_kind,
                            "evidence_kind": "none",
                            "source_type": "none",
                            "source_reference": "none",
                            "adapter": "none",
                            "input_state": "none",
                            "policy_status": state["policy"]["status"],
                            "binding_state": artifact_evidence["binding_state"],
                            "derived_maturity_state": state["maturity_state"],
                            "governed_maturity_state": state["governance"]["governed_maturity_state"],
                            "freshness_state": state["freshness_state"],
                            "precedence_outcome": "not_applicable" if state["maturity_state"] == "not_applicable" else "none",
                            "collection_method": "none",
                            "maturity": "planned",
                            "confidence": "low",
                            "last_verified": "not-verified",
                            "limitations": "none-documented",
                        }
                    )
                    continue
                for source in entry["sources"]:
                    precedence_outcome = "selected" if selected and source["reference"] == selected["reference"] and source["evidence_subject_id"] == selected["evidence_subject_id"] else "supporting"
                    rows.append(
                        {
                            "architecture_subject": subject["mapping"]["element_name"],
                            "evidence_subject": entry["evidence_subject_id"],
                            "subject_variant": entry["subject_variant"],
                            "runtime_unit": entry["runtime_unit"],
                            "owner": subject["owner"],
                            "review_cadence": subject["review_cadence"],
                            "review_status": artifact_evidence["review"]["review_status"],
                            "last_reviewed": artifact_evidence["review"]["last_reviewed"],
                            "reviewed_by": artifact_evidence["review"]["reviewed_by"],
                            "review_notes": artifact_evidence["review"]["review_notes"],
                            "next_review_due": state["governance"]["next_review_due"],
                            "escalation_required": str(state["governance"]["escalation_required"]).lower(),
                            "escalation_status": state["governance"]["escalation_status"],
                            "handoff_to": state["governance"]["handoff_to"],
                            "review_blocking": str(state["governance"]["review_blocking"]).lower(),
                            "artifact_type": artifact_kind,
                            "evidence_kind": source["evidence_kind"],
                            "source_type": source["source_type"],
                            "source_reference": source["reference"],
                            "adapter": source["adapter"],
                            "input_state": source["input_state"],
                            "policy_status": state["policy"]["status"],
                            "binding_state": artifact_evidence["binding_state"],
                            "derived_maturity_state": state["maturity_state"],
                            "governed_maturity_state": state["governance"]["governed_maturity_state"],
                            "freshness_state": state["freshness_state"],
                            "precedence_outcome": precedence_outcome,
                            "collection_method": source["collection_method"],
                            "maturity": source["maturity"],
                            "confidence": source["confidence"],
                            "last_verified": source["last_verified"],
                            "limitations": source["limitations"],
                        }
                    )
    return rows


def csv_text(rows: list[dict[str, str]]) -> str:
    if not rows:
        return ""
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def markdown_table(title: str, intro: str, rows: list[dict[str, str]], columns: list[str], footer: str) -> str:
    lines = [f"# {title}", "", intro, "", "| " + " | ".join(columns) + " |", "| " + " | ".join("---" for _ in columns) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(row[column] for column in columns) + " |")
    lines.extend(["", footer, ""])
    return "\n".join(lines)


def generate_payloads(workspace: dict, mapping: dict, evidence: dict) -> dict[str, bytes]:
    paths = package_paths()
    mapping_subjects = validate_mapping(workspace, mapping)
    evidence_subjects = validate_evidence(mapping_subjects, evidence, paths["root"])
    evaluation_time = parse_timestamp(evidence["defaults"].get("evaluation_date_utc", "")) or datetime.now(timezone.utc)
    artifact_rules = mapping.get("artifact_rules", {})
    elements_by_id = index_elements(workspace["model"])

    subjects = []
    for arch_ref, mapping_subject in mapping_subjects.items():
        subject = dict(mapping_subject)
        subject["review_cadence_days"] = mapping.get("review_cadence_days", {})
        subject["evidence_subjects"] = evidence_subjects[arch_ref]
        subject["artifact_states"] = build_subject_states(subject, artifact_rules, evaluation_time)
        subjects.append(subject)
    subjects.sort(key=lambda item: item["mapping"]["element_name"])

    files: dict[str, bytes] = {}
    manifest_subjects = []

    for subject in subjects:
        container = subject["container"]
        props = container["properties"]
        slug = slug_from_arch_ref(props["arch.ref"])
        relationships = relationship_summary(container, elements_by_id)
        providers = external_providers(container, elements_by_id)

        files[f"sbom/{slug}.cdx.json"] = json_bytes(sbom_document(subject, relationships, providers))
        if subject["artifacts"]["cbom"]["applicable"]:
            files[f"cbom/{slug}.cdx.json"] = json_bytes(cbom_document(subject, relationships))
        files[f"vex/{slug}.cdx.json"] = json_bytes(vex_document(subject, relationships))

        manifest_subjects.append(
            {
                "architecture_subject": subject["mapping"]["element_name"],
                "arch_ref": props["arch.ref"],
                "bom_ref": subject["mapping"]["bom_ref"],
                "runtime_unit": subject["mapping"]["runtime_unit"],
                "mapping_mode": subject["mapping_mode"],
                "subject_type": subject["subject_type"],
                "subject_kind": subject["subject_kind"],
                "ownership": subject["ownership"],
                "owner": subject["owner"],
                "review_cadence": subject["review_cadence"],
                "escalation_owner": subject["escalation_owner"],
                "deployment_zone": props["deployment.zone"],
                "criticality": props["asset.criticality"],
                "supplier": subject["supplier"],
                "domain_flags": subject["domain_flags"],
                "artifacts": {
                    kind: {
                        "applicable": subject["artifacts"][kind]["applicable"],
                        "status": subject["artifacts"][kind]["status"],
                        "origin": subject["artifacts"][kind]["origin"],
                        "derived_maturity_state": subject["artifact_states"][kind]["maturity_state"],
                        "governed_maturity_state": subject["artifact_states"][kind]["governance"]["governed_maturity_state"],
                        "freshness_state": subject["artifact_states"][kind]["freshness_state"],
                        "selected_source": subject["artifact_states"][kind]["selected_source"],
                        "content_status": subject["artifact_states"][kind]["summary"]["content_status"],
                        "review": subject["artifact_states"][kind]["governance"]["review"],
                        "next_review_due": subject["artifact_states"][kind]["governance"]["next_review_due"],
                        "escalation_required": subject["artifact_states"][kind]["governance"]["escalation_required"],
                        "escalation_status": subject["artifact_states"][kind]["governance"]["escalation_status"],
                        "handoff_to": subject["artifact_states"][kind]["governance"]["handoff_to"],
                        "review_blocking": subject["artifact_states"][kind]["governance"]["review_blocking"],
                    }
                    for kind in ARTIFACT_KINDS
                },
                "provenance": {
                    "derived_maturity_state": subject["artifact_states"]["provenance"]["maturity_state"],
                    "governed_maturity_state": subject["artifact_states"]["provenance"]["governance"]["governed_maturity_state"],
                    "freshness_state": subject["artifact_states"]["provenance"]["freshness_state"],
                    "selected_source": subject["artifact_states"]["provenance"]["selected_source"],
                    "content_status": subject["artifact_states"]["provenance"]["summary"]["content_status"],
                    "review": subject["artifact_states"]["provenance"]["governance"]["review"],
                    "next_review_due": subject["artifact_states"]["provenance"]["governance"]["next_review_due"],
                    "escalation_required": subject["artifact_states"]["provenance"]["governance"]["escalation_required"],
                    "escalation_status": subject["artifact_states"]["provenance"]["governance"]["escalation_status"],
                    "handoff_to": subject["artifact_states"]["provenance"]["governance"]["handoff_to"],
                    "review_blocking": subject["artifact_states"]["provenance"]["governance"]["review_blocking"],
                },
                "evidence_subjects": [
                    {
                        "evidence_subject_id": item["evidence_subject_id"],
                        "subject_variant": item["subject_variant"],
                        "subject_kind": item["subject_kind"],
                        "runtime_unit": item["runtime_unit"],
                        "review": item["review"],
                    }
                    for item in subject["evidence_subjects"]
                ],
                "files": {
                    "sbom": f"bom/sbom/{slug}.cdx.json",
                    "vex": f"bom/vex/{slug}.cdx.json",
                },
            }
        )
        if subject["artifacts"]["cbom"]["applicable"]:
            manifest_subjects[-1]["files"]["cbom"] = f"bom/cbom/{slug}.cdx.json"

    coverage_rows = build_coverage_rows(subjects)
    evidence_rows = build_evidence_rows(subjects)

    files["coverage-matrix.csv"] = csv_text(coverage_rows).encode("utf-8")
    files["coverage-matrix.md"] = markdown_table(
        "Supply-Chain Coverage Matrix",
        "This file is generated from the architecture, policy, and decomposed evidence subject layers.",
        coverage_rows,
        ["architecture_subject", "runtime_unit", "deployment_zone", "criticality", "subject_type", "owner", "review_cadence", "sbom", "cbom", "vex", "generated_files"],
        "Coverage states are rule-derived. They only count as real evidence-backed when a non-placeholder, admissible input is actually attached.",
    ).encode("utf-8")
    files["evidence-matrix.csv"] = csv_text(evidence_rows).encode("utf-8")
    files["evidence-matrix.md"] = markdown_table(
        "Supply-Chain Evidence Matrix",
        "This file shows evidence subjects, evidence kinds, and which source won under the current admissibility and precedence rules.",
        evidence_rows,
        [
            "architecture_subject",
            "evidence_subject",
            "subject_variant",
            "runtime_unit",
            "owner",
            "review_cadence",
            "review_status",
            "last_reviewed",
            "reviewed_by",
            "review_notes",
            "next_review_due",
            "escalation_required",
            "escalation_status",
            "handoff_to",
            "review_blocking",
            "artifact_type",
            "evidence_kind",
            "source_type",
            "adapter",
            "input_state",
            "policy_status",
            "derived_maturity_state",
            "governed_maturity_state",
            "freshness_state",
            "precedence_outcome",
        ],
        "A selected source is the current best admissible source for that artifact type. Supporting sources still matter, but they did not win precedence. Real local files appear with input_state=local-file. Governed maturity reflects review blocking when stale or expired evidence needs escalation.",
    ).encode("utf-8")

    manifest = {
        "schema_version": "7.0",
        "source_of_truth": "model/workspace.dsl",
        "derived_from": "model/workspace.json",
        "policy_file": "model/supply-chain-mapping.yaml",
        "evidence_file": "model/supply-chain-evidence.yaml",
        "generation_basis": "Structurizr architecture metadata plus policy mapping plus decomposed evidence subjects plus normalized evidence adapters",
        "evaluation_date_utc": evidence["defaults"].get("evaluation_date_utc", ""),
        "workspace_json_sha256": sha256_bytes(json_bytes(workspace)),
        "policy_sha256": sha256_bytes(json_bytes(mapping)),
        "evidence_sha256": sha256_bytes(json_bytes(evidence)),
        "tracked_subject_count": len(manifest_subjects),
        "tracked_subjects": manifest_subjects,
    }
    files["manifest.json"] = json_bytes(manifest)
    return files


def write_outputs(root: Path, files: dict[str, bytes]) -> None:
    for relative_path, content in files.items():
        path = root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)


def expected_hashes(files: dict[str, bytes]) -> dict[str, str]:
    return {path: sha256_bytes(content) for path, content in files.items()}


def actual_hashes(root: Path, expected_paths: list[str]) -> dict[str, str]:
    hashes = {}
    for relative_path in expected_paths:
        path = root / relative_path
        if path.exists():
            hashes[relative_path] = sha256_file(path)
    return hashes


def sync() -> None:
    paths = package_paths()
    files = generate_payloads(read_json(paths["workspace_json"]), read_json_like_yaml(paths["mapping"]), read_json_like_yaml(paths["evidence"]))
    write_outputs(paths["bom_root"], files)
    print(f"Generated CycloneDX scaffolds in {paths['bom_root']}")


def check() -> int:
    paths = package_paths()
    files = generate_payloads(read_json(paths["workspace_json"]), read_json_like_yaml(paths["mapping"]), read_json_like_yaml(paths["evidence"]))
    expected = expected_hashes(files)
    actual = actual_hashes(paths["bom_root"], sorted(expected))
    print(f"tracked artifact count: {len(actual)}")
    print(f"expected artifact count: {len(expected)}")
    print(f"artifact byte match: {actual == expected}")
    if actual != expected:
        missing = sorted(set(expected) - set(actual))
        changed = sorted(path for path in set(actual) & set(expected) if actual[path] != expected[path])
        if missing:
            print(f"missing: {missing}")
        if changed:
            print(f"changed: {changed}")
        return 2
    return 0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="Verify tracked CycloneDX scaffolds match generated output.")
    args = parser.parse_args()
    if args.check:
        raise SystemExit(check())
    sync()


if __name__ == "__main__":
    main()
