# Vulnerability: Dahua Web Service Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`dahua-web-panel.yaml`)

## Description
A Dahua admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

