# Vulnerability: WordPress Importer - Error Log Disclosure
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-importer-log-disclosure.yaml`)

## Description
Detected WordPress Importer plugin error log file, potentially revealing file paths, errors, and sensitive information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/wordpress-importer/error_log
```

