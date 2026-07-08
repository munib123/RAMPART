# Vulnerability: Jeedom Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`jeedom-panel.yaml`)

## Description
Jeedom login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php?v=d
```

