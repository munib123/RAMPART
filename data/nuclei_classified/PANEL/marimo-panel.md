# Vulnerability: Marimo Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`marimo-panel.yaml`)

## Description
Marimo is an open-source reactive Python notebook and app framework that replaces Jupyter
with git-friendly, reproducible notebooks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

