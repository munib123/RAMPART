# Vulnerability: Pulsar360 Admin Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`pulsar360-admin-panel.yaml`)

## Description
Pulsar360 admin panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/config.php
```

