# Vulnerability: Cyber Stealer C2 Panel - Detect
**Classification:** C2
**Source:** Nuclei Template (`cyber-stealer-panel.yaml`)

## Description
Cyber Stealer C2 Login Panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/webpanel/panel/login.php
```

