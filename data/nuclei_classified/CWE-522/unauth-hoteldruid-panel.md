# Vulnerability: Hoteldruid Management Panel Access
**Classification:** CWE-522
**Source:** Nuclei Template (`unauth-hoteldruid-panel.yaml`)

## Description
A vulnerability in Hoteldruid Panel allows remote unauthenticated users access to the management portal without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/hoteldruid/inizio.php
GET {{BaseURL}}/inizio.php
```

