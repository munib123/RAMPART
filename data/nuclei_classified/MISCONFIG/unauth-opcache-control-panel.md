# Vulnerability: Opcache control Panel - Unauthenticated Access
**Classification:** MISCONFIG
**Source:** Nuclei Template (`unauth-opcache-control-panel.yaml`)

## Description
Opcache control Panel is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/ocp.php
```

