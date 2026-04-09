# Generated Data

This directory is for generated outputs, not hand-authored source data.

The AI risk example now reads from [`../model/workspace.json`](../model/workspace.json) and writes its output into `data/generated/`.

Run:

```bash
python3 code/atlas_risk_matrix.py
```

The generated report is derived from modeled tags, descriptions, technologies, and relationship descriptions in the packaged Structurizr model.
