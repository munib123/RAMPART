# Vulnerability: phpMyAdmin Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`phpmyadmin-panel.yaml`)

## Description
phpMyAdmin panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

