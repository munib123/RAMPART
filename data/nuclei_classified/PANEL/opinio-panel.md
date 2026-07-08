# Vulnerability: Opinio Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`opinio-panel.yaml`)

## Description
Opinio login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/folder.do
GET {{BaseURL}}
```

