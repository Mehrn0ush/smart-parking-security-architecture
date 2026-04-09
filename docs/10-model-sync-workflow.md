# Model Sync Workflow

## Why This Exists

This package includes:

- [`../model/workspace.dsl`](../model/workspace.dsl)
- [`../model/workspace.json`](../model/workspace.json)

The DSL is the source of truth. The JSON is a generated/exported artifact for tooling. To avoid drift, use the generation and verification script.

## Sync Command

From the package root:

```bash
python3 tools/sync_workspace_model.py
```

This generates `model/workspace.json` from `model/workspace.dsl` using `structurizr-cli` and writes:

- `model/manifest.json`

## Verification Command

```bash
python3 tools/sync_workspace_model.py --check
```

This verifies:

- `model/workspace.json` matches the JSON generated from `model/workspace.dsl`
- the packaged JSON is consistent with the packaged DSL

Important note:

- `structurizr-cli` exports contain some volatile identifier values
- verification therefore uses semantic comparison, not raw byte-for-byte equality

## Teaching Point

For students and junior engineers, this is an important lesson: if a repository ships both a source model and an exported artifact, there must be a reproducible way to regenerate and verify the export.
