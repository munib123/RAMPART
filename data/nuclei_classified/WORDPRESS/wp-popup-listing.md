# Vulnerability: WordPress Popup Plugin Directory Listing
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-popup-listing.yaml`)

## Description
Searches for sensitive directories present in the wordpress-popup plugin.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/wordpress-popup/views/admin/
```

