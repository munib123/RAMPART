# Nuclei Template: Batflat SQLite Database - Exposure
**Template ID:** batflat-sqlite-exposure
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-219
**Source:** Nuclei Template (`batflat-sqlite-exposure.yaml`)

## Vulnerability Information & PoC

## Description
Detected exposed Batflat CMS SQLite database files that may contain sensitive information including admin credentials, user data, site configuration, and content. Batflat stores its database in the /inc/data/ directory by default.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/inc/data/database.sdb
```

## References
- https://batflat.org/
- https://github.com/sruupl/batflat
