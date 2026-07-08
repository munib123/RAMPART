# Vulnerability: Druid Monitor Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`druid-panel.yaml`)

## Description
Druid Monitor login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/druid/login.html
```

