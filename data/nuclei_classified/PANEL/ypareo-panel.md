# Vulnerability: YPAREO Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`ypareo-panel.yaml`)

## Description
YPAREO was detected — an Enterprise Resource Planning system.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php
GET {{BaseURL}}/net-ypareo/index.php
GET {{BaseURL}}/netypareo/index.php
GET {{BaseURL}}/index.html
```

