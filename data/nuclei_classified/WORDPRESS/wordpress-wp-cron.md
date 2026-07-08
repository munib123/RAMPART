# Vulnerability: Wordpress wp-cron.php DOS
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wordpress-wp-cron.yaml`)

## Description
When this file is accessed a heavy MySQL query is performed, so it could be used by attackers to cause a DoS.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/wp-cron.php
```

