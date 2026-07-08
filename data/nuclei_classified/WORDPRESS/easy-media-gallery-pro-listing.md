# Vulnerability: WordPress Plugin Media Gallery Pro Listing
**Classification:** WORDPRESS
**Source:** Nuclei Template (`easy-media-gallery-pro-listing.yaml`)

## Description
Searches for sensitive directories present in the easy-media-gallery-pro plugin.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/easy-media-gallery-pro/
```

