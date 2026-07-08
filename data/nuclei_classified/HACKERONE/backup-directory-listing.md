# Vulnerability: Backup Directory Listing - Detect
**Classification:** HACKERONE
**Source:** Nuclei Template (`backup-directory-listing.yaml`)

## Description
Backup Directory Listing folder was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/backup/
GET {{BaseURL}}/php/backup/
```

