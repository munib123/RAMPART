# Vulnerability: ActionTec Modem Advanced Setup Login Panel
**Classification:** CWE-200
**Source:** Nuclei Template (`advance-setup.yaml`)

## Description
An ActionTec Modem Advanced Setup login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/webcm?getpage=../html/login.html
```

