# Vulnerability: WordPress Plugin Iwp-client Listing
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-iwp-client-listing.yaml`)

## Description
Searches for sensitive directories present in the iwp-client plugin.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/iwp-client/
```

