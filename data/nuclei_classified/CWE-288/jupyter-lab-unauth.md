# Vulnerability: Jupyter Lab - Unauthenticated Access
**Classification:** CWE-288
**Source:** Nuclei Template (`jupyter-lab-unauth.yaml`)

## Description
JupyterLab was able to be accessed without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/lab/api/settings/
```

