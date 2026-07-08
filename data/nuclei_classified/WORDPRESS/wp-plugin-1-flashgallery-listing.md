# Vulnerability: WordPress 1 flash gallery listing
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-plugin-1-flashgallery-listing.yaml`)

## Description
Searches for sensitive directories present in the 1-flash-gallery plugin.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/1-flash-gallery/
GET {{BaseURL}}/blog/wp-content/plugins/1-flash-gallery/
```

