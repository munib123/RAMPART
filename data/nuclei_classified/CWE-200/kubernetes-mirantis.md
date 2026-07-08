# Vulnerability: Mirantis Kubernetes Engine Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`kubernetes-mirantis.yaml`)

## Description
Mirantis Kubernetes Engine panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

