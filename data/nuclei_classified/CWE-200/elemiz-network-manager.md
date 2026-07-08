# Vulnerability: Elemiz Network Manager Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`elemiz-network-manager.yaml`)

## Description
Elemiz Network Manager login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/login/
```

