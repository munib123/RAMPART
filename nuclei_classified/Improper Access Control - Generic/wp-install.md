# Nuclei Template: WordPress Exposed Installation
**Template ID:** wp-install
**Vulnerability Class:** Improper Access Control - Generic
**Severity:** Critical
**CWE:** CWE-284
**Source:** Nuclei Template (`wp-install.yaml`)

## Vulnerability Information & PoC

## Description
Wordpress installation files have been detected

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-admin/install.php?step=1
```

## References
- https://smaranchand.com.np/2020/04/misconfigured-wordpress-takeover-to-remote-code-execution/
- https://x.com/0xPugal/status/1610315762392268802
