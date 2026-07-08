# Vulnerability: ASP-Nuke - Open Redirect
**Classification:** CWE-601
**Source:** Nuclei Template (`aspnuke-openredirect.yaml`)

## Description
ASP-Nuke contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/gotoURL.asp?url=interact.sh&id=43569
```

