# Vulnerability: Combodo iTop Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`itop-panel.yaml`)

## Description
Combodo iTop login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/pages/UI.php
GET {{BaseURL}}/simple/pages/UI.php
```

