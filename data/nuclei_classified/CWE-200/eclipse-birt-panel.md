# Vulnerability: Eclipse BIRT Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`eclipse-birt-panel.yaml`)

## Description
Eclipse BIRT (Business Intelligence Reporting Tool) detected

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/reportviewer/
GET {{BaseURL}}/birt/
GET {{BaseURL}}/birt-viewer/
```

