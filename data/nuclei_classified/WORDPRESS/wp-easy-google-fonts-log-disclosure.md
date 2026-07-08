# Vulnerability: WordPress Easy Google Fonts - Error Log Disclosure
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-easy-google-fonts-log-disclosure.yaml`)

## Description
Detected WordPress Easy Google Fonts plugin debug log file, potentially revealing file paths, errors, and sensitive information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/easy-google-fonts/error_log
```

