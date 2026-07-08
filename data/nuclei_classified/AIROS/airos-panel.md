# Vulnerability: AirOS Panel - Detect
**Classification:** AIROS
**Source:** Nuclei Template (`airos-panel.yaml`)

## Description
AirOS panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.cgi?uri=/
```

