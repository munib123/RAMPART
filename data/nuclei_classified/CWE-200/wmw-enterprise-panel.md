# Vulnerability: WMW Enterprise Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`wmw-enterprise-panel.yaml`)

## Description
WMW Enterprise login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/en/login
```

