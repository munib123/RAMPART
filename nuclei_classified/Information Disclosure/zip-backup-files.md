# Nuclei Template: Compressed Backup File - Detect
**Template ID:** zip-backup-files
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`zip-backup-files.yaml`)

## Vulnerability Information & PoC

## Description
Multiple compressed backup files were detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/{{FILENAME}}.{{EXT}}
```

