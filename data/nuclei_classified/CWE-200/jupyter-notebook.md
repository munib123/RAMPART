# Vulnerability: Jupyter Notebook Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`jupyter-notebook.yaml`)

## Description
Jupyter Notebook login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/jupyter/login
GET {{BaseURL}}/jupyter/lab
GET {{BaseURL}}/jupyter/hub/lti/launch
GET {{BaseURL}}/hub/login
```

