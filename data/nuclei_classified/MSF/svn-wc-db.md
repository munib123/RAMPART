# Vulnerability: SVN wc.db File Exposure
**Classification:** MSF
**Source:** Nuclei Template (`svn-wc-db.yaml`)

## Description
SVN wc.db file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.svn/wc.db
GET {{BaseURL}}/wc.db
```

