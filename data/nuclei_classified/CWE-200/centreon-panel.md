# Vulnerability: Centreon Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`centreon-panel.yaml`)

## Description
Centreon login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/centreon/index.php
```

