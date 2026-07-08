# Vulnerability: WordPress Total Upkeep Database and Files Backup Download
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wordpress-total-upkeep-backup-download.yaml`)

## Description
Exposed sensitive file in WordPress Total Upkeep wordpress plugin feature used.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/boldgrid-backup/cron/restore-info.json
```

