# Vulnerability: WordPress DB Backup
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wordpress-db-backup.yaml`)

## Description
This template checks for exposed database in wordpress.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/backup-db/
```

