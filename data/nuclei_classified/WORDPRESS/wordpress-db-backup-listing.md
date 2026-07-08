# Vulnerability: WordPress DB Backup
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wordpress-db-backup-listing.yaml`)

## Description
WordPress DB Backup plugin exposes db file along with directory listing.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/uploads/database-backups/
```

