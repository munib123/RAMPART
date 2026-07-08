# Vulnerability: Kubernetes Local Cluster Web View Panel- Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`kubernetes-web-view.yaml`)

## Description
Kubernetes local cluster web view panel discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/clusters/local
```

