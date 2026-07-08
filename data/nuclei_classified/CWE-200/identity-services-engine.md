# Vulnerability: Cisco Identity Services Engine Admin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`identity-services-engine.yaml`)

## Description
Cisco Identity Services Engine admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/admin/
```

