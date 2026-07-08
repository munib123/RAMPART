# Vulnerability: Kubernetes Dashboard Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`kubernetes-dashboard.yaml`)

## Description
Kubernetes Dashboard panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

