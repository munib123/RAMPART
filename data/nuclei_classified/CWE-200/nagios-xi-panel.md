# Vulnerability: Nagios XI Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`nagios-xi-panel.yaml`)

## Description
Nagios XI login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/nagiosxi/login.php
```

