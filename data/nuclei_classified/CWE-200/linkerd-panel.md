# Vulnerability: Linkerd Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`linkerd-panel.yaml`)

## Description
Linkerd panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/namespaces
```

