# Vulnerability: Mozilla Pollbot - Open Redirect
**Classification:** CWE-601
**Source:** Nuclei Template (`pollbot-redirect.yaml`)

## Description
Mozilla Pollbot contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/%0A/interact.sh/
```

