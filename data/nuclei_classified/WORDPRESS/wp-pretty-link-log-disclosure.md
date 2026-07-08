# Vulnerability: WordPress Pretty Link - Error Log Disclosure
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-pretty-link-log-disclosure.yaml`)

## Description
Detected WordPress Pretty Link plugin debug log file, potentially revealing file paths, errors, and sensitive information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/pretty-link/error_log
```

