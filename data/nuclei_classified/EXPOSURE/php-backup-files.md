# Vulnerability: PHP Source - Backup File Information Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`php-backup-files.yaml`)

## Description
PHP Source File is disclosed to external users.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}{{filepath}}{{bakext}}
```

