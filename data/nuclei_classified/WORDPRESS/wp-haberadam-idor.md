# Vulnerability: WordPress Themes Haberadam JSON API - IDOR and Path Disclosure
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-haberadam-idor.yaml`)

## Description
This template is designed to detect a misconfiguration vulnerability in WordPress themes that use the Haberadam JSON API. This vulnerability can lead to an Insecure Direct Object Reference (IDOR) and path disclosure, potentially exposing sensitive information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/themes/haberadam/api/mobile-info.php?id=
GET {{BaseURL}}/blog/wp-content/themes/haberadam/api/mobile-info.php?id=
```

