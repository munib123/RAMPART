# Vulnerability: Kube API Version
**Classification:** TECH
**Source:** Nuclei Template (`kube-api-version.yaml`)

## Description
Searches for exposed Kubernetes API servers which return version information unauthenticated

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/version
```

