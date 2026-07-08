# Vulnerability: SQLite History - Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`sqlite-history-exposure.yaml`)

## Description
Detects exposed .sqlite_history files. These files contain SQLite command history, including executed queries, table names, and potentially sensitive data that was queried or inserted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.sqlite_history
```

