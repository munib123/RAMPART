# Vulnerability: Wordpress User Enumeration
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wordpress-user-enum.yaml`)

## Description
This template detects user enumeration in wordpress.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?author=1
```

