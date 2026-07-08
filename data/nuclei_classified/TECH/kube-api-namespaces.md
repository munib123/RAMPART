# Vulnerability: Kube API Namespaces
**Classification:** TECH
**Source:** Nuclei Template (`kube-api-namespaces.yaml`)

## Description
Scans for kube namespaces

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/v1/namespaces
```

