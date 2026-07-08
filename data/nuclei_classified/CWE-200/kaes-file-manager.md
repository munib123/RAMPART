# Vulnerability: Kae's File Manager Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`kaes-file-manager.yaml`)

## Description
Kae's File Manager login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/kfm/index.php
```

