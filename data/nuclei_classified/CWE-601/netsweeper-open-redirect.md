# Vulnerability: Netsweeper 4.0.9 - Open Redirect
**Classification:** CWE-601
**Source:** Nuclei Template (`netsweeper-open-redirect.yaml`)

## Description
Netsweeper 4.0.9 contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/webadmin/authportal/bounce.php?url=https://interact.sh/
```

