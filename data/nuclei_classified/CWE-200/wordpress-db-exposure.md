# Vulnerability: WordPress Database Backup File - Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`wordpress-db-exposure.yaml`)

## Description
Detected WordPress database backup files that were publicly accessible, exposing sensitive data including user credentials, email addresses, and site content.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

