# Vulnerability: Batflat SQLite Database - Exposure
**Classification:** CWE-219,CWE-552
**Source:** Nuclei Template (`batflat-sqlite-exposure.yaml`)

## Description
Detected exposed Batflat CMS SQLite database files that may contain sensitive information including admin credentials, user data, site configuration, and content. Batflat stores its database in the /inc/data/ directory by default.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/inc/data/database.sdb
```

