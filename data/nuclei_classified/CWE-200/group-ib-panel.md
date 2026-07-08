# Vulnerability: Group-IB Managed XDR Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`group-ib-panel.yaml`)

## Description
Group-IB Managed XDR login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

