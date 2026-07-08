# Vulnerability: ipTIME Router Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`iptime-router.yaml`)

## Description
ipTIME router login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/sess-bin/login_session.cgi
```

