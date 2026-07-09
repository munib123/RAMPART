# Nuclei Template: PhpMyAdmin Setup File - Detect
**Template ID:** phpmyadmin-setup
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`phpmyadmin-setup.yaml`)

## Vulnerability Information & PoC

## Description
Multiple phpMyAdmin setup files were detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

