# Vulnerability: OpenX/Revive Adserver Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`openx-panel.yaml`)

## Description
OpenX login panel was detected. Note that OpenX is now a Revive Adserver.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/www/admin/index.php
GET {{BaseURL}}/admin/index.php
```

