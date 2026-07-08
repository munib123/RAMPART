# Vulnerability: RemKon Device Manager Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`remkon-manager-panel.yaml`)

## Description
RemKon Device Manager login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.php
```

