# Vulnerability: WordPress Age Gate <2.13.5 - Open Redirect
**Classification:** CWE-601
**Source:** Nuclei Template (`age-gate-open-redirect.yaml`)

## Description
WordPress Age Gate plugin before 2.13.5 contains an open redirect vulnerability via the  _wp_http_referer parameter after certain actions and after invalid or missing nonces. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{BaseURL}}/wp-admin/admin-post.php
```

