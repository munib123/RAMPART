# Vulnerability: PostgreSQL History - Exposure
**Classification:** POSTGRES
**Source:** Nuclei Template (`postgres-history-exposure.yaml`)

## Description
Exposed PostgreSQL history files (.psql_history) were detected. These files contain a record of executed SQL commands and may disclose sensitive information like passwords, database schemas, and query logic.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.psql_history
GET {{BaseURL}}/psql_history
GET {{BaseURL}}/.postgresql_history
```

