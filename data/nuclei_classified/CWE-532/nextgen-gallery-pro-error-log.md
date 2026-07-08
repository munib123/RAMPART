# Vulnerability: WordPress NextGEN Gallery Pro - Error Log Disclosure
**Classification:** CWE-532
**Source:** Nuclei Template (`nextgen-gallery-pro-error-log.yaml`)

## Description
The NextGEN Gallery Pro plugin for WordPress may expose debug/error log files that contain sensitive information including file paths, database queries, and potentially credentials. These log files are accessible without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/wp-content/debug.log
```

