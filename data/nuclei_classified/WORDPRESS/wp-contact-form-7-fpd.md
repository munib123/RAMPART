# Vulnerability: WordPress Contact Form 7 - Full Path Disclosure
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-contact-form-7-fpd.yaml`)

## Description
The WordPress Contact Form 7 plugin was detected to be vulnerable to Full Path Disclosure, where direct access to PHP files revealed the full server filesystem path and could aid further exploitation.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/contact-form-7/includes/functions.php
```

