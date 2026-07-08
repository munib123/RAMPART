# Vulnerability: PhpMyAdmin Server Import Page - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`phpmyadmin-server-import.yaml`)

## Description
Multiple phpMyAdmin server import pages were detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

