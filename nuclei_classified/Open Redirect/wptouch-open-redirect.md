# Nuclei Template: WordPress WPtouch 3.x - Open Redirect
**Template ID:** wptouch-open-redirect
**Vulnerability Class:** Open Redirect
**Severity:** Medium
**CWE:** CWE-601
**Source:** Nuclei Template (`wptouch-open-redirect.yaml`)

## Vulnerability Information & PoC

## Description
WordPress WPtouch plugin 3.x contains an open redirect vulnerability. The plugin fails to properly sanitize user-supplied input. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/?wptouch_switch=desktop&redirect=https://interact.sh/
```

## References
- https://cxsecurity.com/issue/WLB-2020030114
