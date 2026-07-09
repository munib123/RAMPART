# Nuclei Template: Thinkific - Open Redirect
**Template ID:** thinkific-redirect
**Vulnerability Class:** Open Redirect
**Severity:** Medium
**CWE:** CWE-601
**Source:** Nuclei Template (`thinkific-redirect.yaml`)

## Vulnerability Information & PoC

## Description
Thinkific contains an open redirect vulnerability via the http://interact.sh URL. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/api/sso/v2/sso/jwt?error_url=http://interact.sh
```

## References
- https://gitlab.austinoneil.com/aoneil/bb-automation/-/blob/master/tools/nuclei-templates/vulnerabilities/other/thinkific-redirect.yaml
