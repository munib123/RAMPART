# Nuclei Template: WordPress Database Backup File - Exposure
**Template ID:** wordpress-db-exposure
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`wordpress-db-exposure.yaml`)

## Vulnerability Information & PoC

## Description
Detected WordPress database backup files that were publicly accessible, exposing sensitive data including user credentials, email addresses, and site content.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

## References
- https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
- https://wordpress.org/support/article/backing-up-your-database/
