# Vulnerability: Avatier Password Management Panel
**Classification:** CWE-200
**Source:** Nuclei Template (`avatier-password-management.yaml`)

## Description
An Avatier password management panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/aims/ps/
```

