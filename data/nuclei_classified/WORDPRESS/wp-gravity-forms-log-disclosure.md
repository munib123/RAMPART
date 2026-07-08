# Vulnerability: WordPress Gravity Forms - Log File Disclosure
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-gravity-forms-log-disclosure.yaml`)

## Description
The Gravity Forms plugin for WordPress stores log files that may be accessible without authentication. When logging is enabled, debug and error logs are created in the wp-content/uploads/gravity_forms/logs/ directory. These logs can contain sensitive information including form submission data, file paths, database queries, PHP errors, API keys, and user information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/gravityforms/debug.log
GET {{BaseURL}}/wp-content/plugins/gravityforms/tmp/debug.log
```

