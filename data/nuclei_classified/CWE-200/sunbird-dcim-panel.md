# Vulnerability: Sunbird DCIM - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sunbird-dcim-panel.yaml`)

## Description
Sunbird DCIM login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/dcim/
```

