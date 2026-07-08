# Vulnerability: SQLiteManager - Text Display
**Classification:** MISCONFIG
**Source:** Nuclei Template (`exposed-sqlite-manager.yaml`)

## Description
SQLiteManager panel contains inconsistent text display in title and text.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/sqlite/
GET {{BaseURL}}/sqlitemanager/
```

