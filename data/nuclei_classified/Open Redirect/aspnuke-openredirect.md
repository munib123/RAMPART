# Nuclei Template: ASP-Nuke - Open Redirect
**Template ID:** aspnuke-openredirect
**Vulnerability Class:** Open Redirect
**Severity:** Medium
**CWE:** CWE-601
**Source:** Nuclei Template (`aspnuke-openredirect.yaml`)

## Vulnerability Information & PoC

## Description
ASP-Nuke contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/gotoURL.asp?url=interact.sh&id=43569
```

## References
- https://packetstormsecurity.com/files/125931/ASP-Nuke-2.0.7-Open-Redirect.html
