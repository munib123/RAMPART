# Vulnerability: Kubernetes Enterprise Manager Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`kubernetes-enterprise-manager.yaml`)

## Description
Kubernetes Enterprise Manager panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

