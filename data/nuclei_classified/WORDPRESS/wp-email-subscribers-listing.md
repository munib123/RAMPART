# Vulnerability: WordPress Plugin Email Subscribers Listing
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-email-subscribers-listing.yaml`)

## Description
Searches for sensitive directories present in the email-subscribers plugin.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/email-subscribers
```

