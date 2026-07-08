# Vulnerability: WordPress Plugin Sfwd-lms Listing
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-sfwd-lms-listing.yaml`)

## Description
Searches for sensitive directories present in the sfwd-lms plugin.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/sfwd-lms/
```

