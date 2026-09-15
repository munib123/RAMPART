# Nuclei Template: PhpMyAdmin Server Import Page - Detect
**Template ID:** pma-server-import
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`phpmyadmin-server-import.yaml`)

## Vulnerability Information & PoC

## Description
Multiple phpMyAdmin server import pages were detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

