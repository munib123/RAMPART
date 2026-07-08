# Vulnerability: Microsoft Exchange Server End-of-Life - Detect
**Classification:** TECH
**Source:** Nuclei Template (`msexchange-eol.yaml`)

## Description
Detected Microsoft Exchange Server versions that have reached End-of-Life (EOL) and no longer receive security updates.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/owa/
GET {{BaseURL}}/owa/auth/logon.aspx
```

