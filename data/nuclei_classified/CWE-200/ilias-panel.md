# Vulnerability: ILIAS Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ilias-panel.yaml`)

## Description
ILIAS login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.php
GET {{BaseURL}}/ilias/login.php
```

