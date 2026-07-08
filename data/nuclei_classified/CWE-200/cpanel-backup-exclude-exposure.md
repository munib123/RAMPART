# Vulnerability: cPanel Backup Exclusion Configuration - Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`cpanel-backup-exclude-exposure.yaml`)

## Description
cPanel backup exclusion configuration file (cpbackup-exclude.conf) was publicly accessible, potentially exposing directory structure and system paths.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cpbackup-exclude.conf
GET {{BaseURL}}/.cpbackup-exclude.conf
```

