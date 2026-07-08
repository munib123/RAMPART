# Vulnerability: WordPress bbPress Plugin - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-bbpress-fpd.yaml`)

## Description
WordPress plugin bbPress internal file system path was disclosed through direct access to the plugin's main PHP file.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/bbpress/templates/default/extras/single-forum.php
```

