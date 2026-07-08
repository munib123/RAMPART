# Vulnerability: JupyterHub Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`jupyterhub-panel.yaml`)

## Description
JupyterHub is a multi-user server for Jupyter notebooks

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/hub/login
```

