# Vulnerability: Firebase Debug Log File Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`firebase-debug-log.yaml`)

## Description
Firebase debug log file was exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/firebase-debug.log
```

