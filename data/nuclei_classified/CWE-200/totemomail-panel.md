# Vulnerability: Totemomail Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`totemomail-panel.yaml`)

## Description
Totemomail login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/responsiveUI/
GET {{BaseURL}}/responsiveUI/webmail/folder.xhtml
```

