# Vulnerability: OpenSIS Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`opensis-panel.yaml`)

## Description
OpenSIS login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/opensis/index.php
```

