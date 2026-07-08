# Vulnerability: Wordpress directory listing
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wordpress-directory-listing.yaml`)

## Description
Directory listing enabled in wordpress.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/uploads/
GET {{BaseURL}}/wp-content/themes/
GET {{BaseURL}}/wp-content/plugins/
GET {{BaseURL}}/wp-includes/
```

