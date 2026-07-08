# Vulnerability: osTicket Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`osticket-panel.yaml`)

## Description
osTicket login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/login.php
```

