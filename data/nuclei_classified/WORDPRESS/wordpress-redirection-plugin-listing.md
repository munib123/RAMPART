# Vulnerability: WordPress Redirection Plugin Directory Listing
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wordpress-redirection-plugin-listing.yaml`)

## Description
Searches for sensitive directories present in the redirection plugin.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/redirection/
```

