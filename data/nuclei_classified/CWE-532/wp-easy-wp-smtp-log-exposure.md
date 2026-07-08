# Vulnerability: WordPress Easy WP SMTP - Log Exposure
**Classification:** CWE-532
**Source:** Nuclei Template (`wp-easy-wp-smtp-log-exposure.yaml`)

## Description
Detected WordPress Easy WP SMTP plugin debug log file exposed via directory listing, potentially revealing sensitive email contents including password reset links.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/easy-wp-smtp/logs/
```

