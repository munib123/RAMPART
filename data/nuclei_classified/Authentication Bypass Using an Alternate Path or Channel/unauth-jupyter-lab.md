# Nuclei Template: Jupyter Lab - Unauthenticated Access
**Template ID:** unauth-jupyter-lab
**Vulnerability Class:** Authentication Bypass Using an Alternate Path or Channel
**Severity:** Critical
**CWE:** CWE-288
**Source:** Nuclei Template (`jupyter-lab-unauth.yaml`)

## Vulnerability Information & PoC

## Description
JupyterLab was able to be accessed without authentication.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/lab/api/settings/
```

## References
- https://paper.seebug.org/2058/
