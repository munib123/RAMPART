# Nuclei Template: SQLiteManager - Text Display
**Template ID:** exposed-sqlite-manager
**Vulnerability Class:** SQL Injection
**Severity:** Medium
**Source:** Nuclei Template (`exposed-sqlite-manager.yaml`)

## Vulnerability Information & PoC

## Description
SQLiteManager panel contains inconsistent text display in title and text.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/sqlite/
GET {{BaseURL}}/sqlitemanager/
```

## References
- https://www.exploit-db.com/ghdb/5003
