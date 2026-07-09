# Nuclei Template: WordPress Attitude 1.1.1 - Open Redirect
**Template ID:** attitude-theme-open-redirect
**Vulnerability Class:** Open Redirect
**Severity:** Medium
**CWE:** CWE-601
**Source:** Nuclei Template (`attitude-theme-open-redirect.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Attitude theme 1.1.1 contains an open redirect vulnerability via the goto.php endpoint. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/themes/Attitude/go.php?https://interact.sh/
```

## References
- https://cxsecurity.com/issue/WLB-2020030185
