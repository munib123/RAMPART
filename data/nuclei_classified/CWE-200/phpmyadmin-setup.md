# Vulnerability: PhpMyAdmin Setup File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`phpmyadmin-setup.yaml`)

## Description
Multiple phpMyAdmin setup files were detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

