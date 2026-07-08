# Vulnerability: WordPress bbPress Plugin Directory Listing
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wordpress-bbpress-plugin-listing.yaml`)

## Description
Searches for sensitive directories present in the bbpress wordpress plugin.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/bbpress/
```

