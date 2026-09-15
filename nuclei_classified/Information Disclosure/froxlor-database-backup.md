# Nuclei Template: Froxlor Server Management Backup File - Detect
**Template ID:** froxlor-database-backup
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`froxlor-database-backup.yaml`)

## Vulnerability Information & PoC

## Description
Froxlor Server Management backup file was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/install/froxlor.sql
```

