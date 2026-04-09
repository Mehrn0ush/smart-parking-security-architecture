#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Syncing packaged model artifacts"
python3 "$ROOT_DIR/tools/sync_workspace_model.py"

echo
echo "==> Verifying packaged model artifacts"
python3 "$ROOT_DIR/tools/sync_workspace_model.py" --check

echo
echo "==> Generating architecture-aware CycloneDX scaffolds"
python3 "$ROOT_DIR/tools/generate_cyclonedx_artifacts.py"

echo
echo "==> Verifying architecture-aware CycloneDX scaffolds"
python3 "$ROOT_DIR/tools/generate_cyclonedx_artifacts.py" --check

echo
echo "==> Generating model-driven AI risk report"
python3 "$ROOT_DIR/code/atlas_risk_matrix.py"

echo
if [[ -n "${SMART_PARKING_GATE_DEMO_SECRET:-}" ]]; then
  echo "==> Running gate command signing demo"
  python3 "$ROOT_DIR/code/secure_command_signing_demo.py"
else
  echo "==> Skipping gate command signing demo"
  echo "Set SMART_PARKING_GATE_DEMO_SECRET to run it."
fi

echo
echo "==> Materials ready"
echo "Read: $ROOT_DIR/README.md"
echo "Model: $ROOT_DIR/model/workspace.dsl"
echo "JSON: $ROOT_DIR/model/workspace.json"
echo "Policy: $ROOT_DIR/model/supply-chain-mapping.yaml"
echo "Evidence: $ROOT_DIR/model/supply-chain-evidence.yaml"
echo "CycloneDX manifest: $ROOT_DIR/bom/manifest.json"
echo "Coverage matrix: $ROOT_DIR/bom/coverage-matrix.md"
echo "Evidence matrix: $ROOT_DIR/bom/evidence-matrix.md"
echo "Learning path: $ROOT_DIR/docs/00-learning-path.md"
echo "Technical view: $ROOT_DIR/docs/06-technical-view.md"
echo "Generated AI risk report: $ROOT_DIR/data/generated/atlas-risk-report.csv"
