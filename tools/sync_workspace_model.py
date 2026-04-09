#!/usr/bin/env python3
"""
Generate and verify packaged model artifacts from the packaged Structurizr DSL.

Source of truth inside this package:
- model/workspace.dsl

Generated artifact inside this package:
- model/workspace.json
- model/manifest.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_workspace_json(value):
    if isinstance(value, dict):
        normalized = {}
        for key, child in value.items():
            if key == "structurizr.dsl.identifier":
                continue
            normalized[key] = normalize_workspace_json(child)
        return normalized
    if isinstance(value, list):
        return [normalize_workspace_json(item) for item in value]
    return value


def semantic_workspace_hash(path: Path) -> str:
    normalized = normalize_workspace_json(json.loads(path.read_text()))
    payload = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def package_paths() -> dict[str, Path]:
    script = Path(__file__).resolve()
    package_root = script.parents[1]
    model_dir = package_root / "model"
    return {
        "package_root": package_root,
        "model_dir": model_dir,
        "workspace_dsl": model_dir / "workspace.dsl",
        "workspace_json": model_dir / "workspace.json",
        "manifest": model_dir / "manifest.json",
    }


def structurizr_cli() -> str:
    cli = shutil.which("structurizr-cli")
    if not cli:
        raise SystemExit(
            "structurizr-cli was not found in PATH. Install it to generate workspace.json from workspace.dsl."
        )
    return cli


def generate_workspace_json(dsl_path: Path) -> Path:
    cli = structurizr_cli()
    with tempfile.TemporaryDirectory() as tmpdir:
        outdir = Path(tmpdir)
        subprocess.run(
            [cli, "export", "-workspace", str(dsl_path), "-format", "json", "-output", str(outdir)],
            check=True,
            capture_output=True,
            text=True,
        )
        generated = outdir / "workspace.json"
        if not generated.exists():
            raise SystemExit("structurizr-cli did not produce workspace.json")
        with tempfile.NamedTemporaryFile(prefix="workspace-generated-", suffix=".json", delete=False) as handle:
            target = Path(handle.name)
        shutil.copy2(generated, target)
        return target


def build_manifest(p: dict[str, Path], generated_json: Path) -> dict:
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_of_truth": "model/workspace.dsl",
        "generated_with": "structurizr-cli export -format json",
        "package_files": {
            "workspace_dsl": "model/workspace.dsl",
            "workspace_json": "model/workspace.json",
        },
        "hashes": {
            "workspace_dsl_sha256": sha256(p["workspace_dsl"]),
            "generated_workspace_json_sha256": sha256(generated_json),
            "packaged_workspace_json_sha256": sha256(p["workspace_json"]),
            "generated_workspace_json_semantic_sha256": semantic_workspace_hash(generated_json),
            "packaged_workspace_json_semantic_sha256": semantic_workspace_hash(p["workspace_json"]),
        },
    }


def sync() -> None:
    p = package_paths()
    p["model_dir"].mkdir(parents=True, exist_ok=True)
    if not p["workspace_dsl"].exists():
        raise SystemExit(f"Missing source DSL: {p['workspace_dsl']}")

    generated_json = generate_workspace_json(p["workspace_dsl"])
    try:
        shutil.copy2(generated_json, p["workspace_json"])
        manifest = build_manifest(p, generated_json)
        p["manifest"].write_text(json.dumps(manifest, indent=2) + "\n")
        print(f"Generated {p['workspace_json']} from {p['workspace_dsl']}")
    finally:
        generated_json.unlink(missing_ok=True)


def check() -> int:
    p = package_paths()
    required = [p["workspace_dsl"], p["workspace_json"]]
    if not all(path.exists() for path in required):
        print("Missing one or more required model files.")
        return 1

    generated_json = generate_workspace_json(p["workspace_dsl"])
    try:
        dsl_hash = sha256(p["workspace_dsl"])
        generated_hash = sha256(generated_json)
        packaged_hash = sha256(p["workspace_json"])
        generated_semantic_hash = semantic_workspace_hash(generated_json)
        packaged_semantic_hash = semantic_workspace_hash(p["workspace_json"])

        print(f"workspace.dsl present: True")
        print(f"workspace.json byte-for-byte match: {packaged_hash == generated_hash}")
        print(f"workspace.json semantic match: {packaged_semantic_hash == generated_semantic_hash}")
        print(f"workspace.dsl sha256: {dsl_hash}")
        print(f"generated workspace.json sha256: {generated_hash}")
        print(f"packaged workspace.json sha256: {packaged_hash}")
        print(f"generated workspace.json semantic sha256: {generated_semantic_hash}")
        print(f"packaged workspace.json semantic sha256: {packaged_semantic_hash}")
        return 0 if packaged_semantic_hash == generated_semantic_hash else 2
    finally:
        generated_json.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="Verify packaged workspace.json matches generated output.")
    args = parser.parse_args()
    if args.check:
        raise SystemExit(check())
    sync()


if __name__ == "__main__":
    main()
