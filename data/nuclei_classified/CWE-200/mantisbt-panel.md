# Vulnerability: MantisBT Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mantisbt-panel.yaml`)

## Description
MantisBT login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login_page.php
```

