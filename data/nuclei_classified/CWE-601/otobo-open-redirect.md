# Vulnerability: Otobo - Open Redirect
**Classification:** CWE-601
**Source:** Nuclei Template (`otobo-open-redirect.yaml`)

## Description
Otobo contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/otobo/index.pl?Action=ExternalURLJump;URL=http://www.interact.sh
```

