# Vulnerability: Piwigo Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`piwigo-panel.yaml`)

## Description
Piwigo login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/identification.php
```

