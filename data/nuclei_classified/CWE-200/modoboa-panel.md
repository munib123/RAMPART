# Vulnerability: Modoboa Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`modoboa-panel.yaml`)

## Description
Modoboa login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/accounts/login/?next=/
```

