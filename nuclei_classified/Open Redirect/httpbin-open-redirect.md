# Nuclei Template: HTTPBin - Open Redirect
**Template ID:** httpbin-open-redirect
**Vulnerability Class:** Open Redirect
**Severity:** Medium
**CWE:** CWE-601
**Source:** Nuclei Template (`httpbin-open-redirect.yaml`)

## Vulnerability Information & PoC

## Description
HTTPBin contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/redirect-to?url=https%3A%2F%2Finteract.sh
```

## References
- https://github.com/postmanlabs/httpbin
