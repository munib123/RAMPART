# Vulnerability: iClock Automatic Data Master Server Admin Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`iclock-admin-panel.yaml`)

## Description
An iClock Automatic Data Master Server Admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/iclock/accounts/login/
GET {{BaseURL}}/iclock/accounts/login/?next=/iclock/data/iclock/
```

