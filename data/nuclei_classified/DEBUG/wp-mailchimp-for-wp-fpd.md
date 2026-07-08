# Vulnerability: WordPress Mailchimp for WordPress Plugin - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-mailchimp-for-wp-fpd.yaml`)

## Description
WordPress plugin MC4WP: Mailchimp for WordPress internal file system path is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/mailchimp-for-wp/integrations/bootstrap.php
```

