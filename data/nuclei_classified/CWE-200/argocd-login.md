# Vulnerability: Argo CD Login Panel
**Classification:** CWE-200
**Source:** Nuclei Template (`argocd-login.yaml`)

## Description
An Argo CD login panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/version
GET {{BaseURL}}/api/v1/settings
```

