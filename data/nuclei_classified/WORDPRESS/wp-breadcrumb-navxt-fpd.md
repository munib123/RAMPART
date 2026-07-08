# Vulnerability: WordPress Breadcrumb NavXT - Full Path Disclosure
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-breadcrumb-navxt-fpd.yaml`)

## Description
The Breadcrumb NavXT plugin for WordPress was detected to be vulnerable to Full Path Disclosure, allowing unauthenticated attackers to obtain the full application path that could aid other attacks when combined with another vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/breadcrumb-navxt/breadcrumb-navxt.php
```

