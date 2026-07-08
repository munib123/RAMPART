# Vulnerability: Altair WordPress theme v4.8 - Directory Listing
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-altair-listing.yaml`)

## Description
Searches for directories listing in the altair theme.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/themes/altair/modules/
GET {{BaseURL}}/wp-content/themes/altair/functions/
GET {{BaseURL}}/wp-content/themes/altair/images/flip/
GET {{BaseURL}}/wp-content/themes/altair/images/
```

