# Vulnerability: Compressed Backup File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`zip-backup-files.yaml`)

## Description
Multiple compressed backup files were detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/{{FILENAME}}.{{EXT}}
```

