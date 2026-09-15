# Nuclei Template: WordPress Age Gate <2.13.5 - Open Redirect
**Template ID:** age-gate-open-redirect
**Vulnerability Class:** Open Redirect
**Severity:** Medium
**CWE:** CWE-601
**Source:** Nuclei Template (`age-gate-open-redirect.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Age Gate plugin before 2.13.5 contains an open redirect vulnerability via the  _wp_http_referer parameter after certain actions and after invalid or missing nonces. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
POST {{BaseURL}}/wp-admin/admin-post.php
```

## References
- https://wpscan.com/vulnerability/10489
- https://packetstormsecurity.com/files/160236/
- https://wordpress.org/plugins/age-gate
