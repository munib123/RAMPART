# Vulnerability: Kube API Secrets
**Classification:** TECH
**Source:** Nuclei Template (`kube-api-secrets.yaml`)

## Description
Scans for kube secrets endpoint

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/v1/namespaces/default/secrets
```

