# Vulnerability: WordPress Plugin GDPR Cookie Consent - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wp-cookie-law-info-fpd.yaml`)

## Description
WordPress GDPR Cookie Consent (cookie-law-info) plugin is vulnerable to full path disclosure via direct access to plugin files.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/cookie-law-info/includes/class-cookie-law-info.php
GET {{BaseURL}}/wp-content/plugins/cookie-law-info/admin/class-cookie-law-info-admin.php
GET {{BaseURL}}/wp-content/plugins/cookie-law-info/legacy/class-cookie-law-info.php
```

