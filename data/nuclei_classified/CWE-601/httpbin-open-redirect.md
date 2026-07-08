# Vulnerability: HTTPBin - Open Redirect
**Classification:** CWE-601
**Source:** Nuclei Template (`httpbin-open-redirect.yaml`)

## Description
HTTPBin contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/redirect-to?url=https%3A%2F%2Finteract.sh
```

