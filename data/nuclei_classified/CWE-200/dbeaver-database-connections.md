# Vulnerability: DBeaver Database Connections - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`dbeaver-database-connections.yaml`)

## Description
DBeaver database connections were detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.dbeaver/data-sources.json
```

