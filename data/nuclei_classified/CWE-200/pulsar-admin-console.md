# Vulnerability: Pulsar Admin Console Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`pulsar-admin-console.yaml`)

## Description
Pulsar admin console panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/#/admin/dashboard
```

