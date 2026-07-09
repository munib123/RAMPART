# Nuclei Template: Hoteldruid Management Panel Access
**Template ID:** unauth-hoteldruid-panel
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`unauth-hoteldruid-panel.yaml`)

## Vulnerability Information & PoC

## Description
A vulnerability in Hoteldruid Panel allows remote unauthenticated users access to the management portal without authentication.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/hoteldruid/inizio.php
GET {{BaseURL}}/inizio.php
```

## References
- https://github.com/nomi-sec/PoC-in-GitHub/blob/master/2021/CVE-2021-42949.json
- https://www.hoteldruid.com/
