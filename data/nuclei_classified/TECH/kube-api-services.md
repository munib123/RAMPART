# Vulnerability: Kube API Services
**Classification:** TECH
**Source:** Nuclei Template (`kube-api-services.yaml`)

## Description
Scans for kube services

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/v1/namespaces/default/services
```

