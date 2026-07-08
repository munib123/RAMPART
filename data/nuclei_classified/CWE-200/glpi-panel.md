# Vulnerability: GLPI Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`glpi-panel.yaml`)

## Description
GLPI panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/CHANGELOG.md
GET {{BaseURL}}/glpi/
```

