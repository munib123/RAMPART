# Vulnerability: WordPress WP Migrate DB - Full Path Disclosure
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-migrate-db-fpd.yaml`)

## Description
The WP Migrate DB (WP Migrate Lite - WordPress Migration Made Easy) plugin for WordPress was detected to be vulnerable to Full Path Disclosure, allowing unauthenticated attackers to obtain the full application path that could aid other attacks when combined with another vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/wp-migrate-db/wp-migrate-db.php
```

