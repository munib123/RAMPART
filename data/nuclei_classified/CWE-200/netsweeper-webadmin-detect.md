# Vulnerability: Netsweeper WebAdmin - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`netsweeper-webadmin-detect.yaml`)

## Description
Netsweeper WebAdmin was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/webadmin/start/
GET {{BaseURL}}/webadmin/tools/systemstatus_remote.php
```

