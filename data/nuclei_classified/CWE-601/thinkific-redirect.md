# Vulnerability: Thinkific - Open Redirect
**Classification:** CWE-601
**Source:** Nuclei Template (`thinkific-redirect.yaml`)

## Description
Thinkific contains an open redirect vulnerability via the http://interact.sh URL. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/sso/v2/sso/jwt?error_url=http://interact.sh
```

