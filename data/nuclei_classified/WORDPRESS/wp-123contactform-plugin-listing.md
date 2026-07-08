# Vulnerability: WordPress 123ContactForm Plugin Directory Listing
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-123contactform-plugin-listing.yaml`)

## Description
Searches for sensitive directories present in the 123contactform-for-wordpress plugin.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/123contactform-for-wordpress/
```

