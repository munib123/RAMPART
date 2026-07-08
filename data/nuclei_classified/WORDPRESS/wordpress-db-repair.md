# Vulnerability: Wordpress DB Repair Exposed
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wordpress-db-repair.yaml`)

## Description
Discover enabled Wordpress repair page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-admin/maint/repair.php
```

