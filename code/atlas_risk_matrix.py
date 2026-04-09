#!/usr/bin/env python3
"""
Generate an AI risk view directly from the packaged Structurizr model.

The script derives risks from modeled tags, descriptions, technologies,
and relationship descriptions in workspace.json rather than relying on a
hand-authored seed file or hardcoded container-name mapping.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class RiskRow:
    component: str
    technique: str
    likelihood: int
    impact: int
    rationale: str
    source_tags: str

    @property
    def risk_score(self) -> int:
        return self.likelihood * self.impact

    @property
    def priority(self) -> str:
        if self.risk_score >= 20:
            return "critical"
        if self.risk_score >= 12:
            return "high"
        if self.risk_score >= 8:
            return "medium"
        return "low"


def package_root() -> Path:
    return Path(__file__).resolve().parents[1]


def load_workspace() -> dict:
    return json.loads((package_root() / "model" / "workspace.json").read_text())


def smart_parking_system(workspace: dict) -> dict:
    for system in workspace.get("model", {}).get("softwareSystems", []):
        if system.get("name") == "Smart Parking System":
            return system
    raise RuntimeError("Smart Parking System not found in workspace.json")


def container_index(system: dict) -> dict[str, dict]:
    return {container["id"]: container for container in system.get("containers", [])}


def container_text(container: dict, lookup: dict[str, dict]) -> str:
    parts = [
        container.get("name", ""),
        container.get("description", ""),
        container.get("technology", ""),
        container.get("tags", ""),
    ]
    for rel in container.get("relationships", []):
        parts.append(rel.get("description", ""))
        parts.append(rel.get("technology", ""))
    return " | ".join(parts).lower()


def modeled_as_ai(text: str) -> bool:
    keywords = [
        "ai/ml",
        "mlops",
        "model",
        "inference",
        "license plate recognition",
        "confidence score",
        "training",
        "analytics service",
    ]
    return any(keyword in text for keyword in keywords)


def derive_risks(container: dict, lookup: dict[str, dict]) -> list[RiskRow]:
    text = container_text(container, lookup)
    tags = container.get("tags", "")
    rows: list[RiskRow] = []

    if not modeled_as_ai(text):
        return rows

    if "license plate recognition" in text or "video" in text or "camera" in text or "image" in text:
        rows.append(
            RiskRow(
                component=container["name"],
                technique="Adversarial Perception Attack",
                likelihood=4 if "high risk" in text else 3,
                impact=5 if "edge zone" in text else 4,
                rationale="Derived from modeled perception/video/image behavior and edge exposure.",
                source_tags=tags,
            )
        )

    if "inference" in text or "ai/ml" in text:
        rows.append(
            RiskRow(
                component=container["name"],
                technique="Inference Data Manipulation",
                likelihood=3,
                impact=4 if "high risk" in text else 3,
                rationale="Derived from modeled inference responsibilities and AI behavior.",
                source_tags=tags,
            )
        )

    if "model" in text and ("registry" in text or "version" in text or "deploy" in text or "pulls latest model versions" in text):
        rows.append(
            RiskRow(
                component=container["name"],
                technique="Model Tampering Or Supply Chain Attack",
                likelihood=2,
                impact=5 if ("mlops" in text or "edge zone" in text) else 4,
                rationale="Derived from modeled model distribution, versioning, or deployment paths.",
                source_tags=tags,
            )
        )

    if "training" in text or "mlops" in text:
        rows.append(
            RiskRow(
                component=container["name"],
                technique="Training Data Manipulation",
                likelihood=2,
                impact=5,
                rationale="Derived from modeled training or MLOps responsibilities.",
                source_tags=tags,
            )
        )

    if "confidence" in text or "monitoring" in text or "metrics" in text:
        rows.append(
            RiskRow(
                component=container["name"],
                technique="Monitoring Or Metric Integrity Evasion",
                likelihood=2,
                impact=3 if "metrics" in text else 4,
                rationale="Derived from modeled monitoring, confidence, or metric collection paths.",
                source_tags=tags,
            )
        )

    if "plugin" in text or "adapter" in text or "pipeline api" in text:
        rows.append(
            RiskRow(
                component=container["name"],
                technique="Extension Or Plugin Abuse",
                likelihood=3,
                impact=4,
                rationale="Derived from modeled extension, plugin, or adapter behavior.",
                source_tags=tags,
            )
        )

    deduped: dict[tuple[str, str], RiskRow] = {}
    for row in rows:
        deduped[(row.component, row.technique)] = row
    return list(deduped.values())


def write_csv(rows: list[RiskRow]) -> Path:
    output_dir = package_root() / "data" / "generated"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "atlas-risk-report.csv"
    with output_path.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            ["component", "technique", "likelihood", "impact", "risk_score", "priority", "rationale", "source_tags"]
        )
        for row in rows:
            writer.writerow(
                [
                    row.component,
                    row.technique,
                    row.likelihood,
                    row.impact,
                    row.risk_score,
                    row.priority,
                    row.rationale,
                    row.source_tags,
                ]
            )
    return output_path


def main() -> None:
    workspace = load_workspace()
    system = smart_parking_system(workspace)
    lookup = container_index(system)
    rows: list[RiskRow] = []
    for container in system.get("containers", []):
        rows.extend(derive_risks(container, lookup))
    rows.sort(key=lambda row: row.risk_score, reverse=True)
    output_path = write_csv(rows)

    print("component,technique,likelihood,impact,risk_score,priority")
    for row in rows:
        print(f"{row.component},{row.technique},{row.likelihood},{row.impact},{row.risk_score},{row.priority}")
    print(f"\nGenerated: {output_path}")


if __name__ == "__main__":
    main()
