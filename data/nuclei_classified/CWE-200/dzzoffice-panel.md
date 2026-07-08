# Vulnerability: DzzOffice Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`dzzoffice-panel.yaml`)

## Description
DzzOffice login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/index.php
GET {{BaseURL}}/user.php?mod=login
```

