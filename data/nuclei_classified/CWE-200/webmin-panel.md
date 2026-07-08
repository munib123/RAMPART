# Vulnerability: Webmin Admin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`webmin-panel.yaml`)

## Description
Webmin admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/webmin/
```

