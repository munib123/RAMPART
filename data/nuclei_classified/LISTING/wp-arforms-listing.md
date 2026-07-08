# Vulnerability: WordPress Plugin Arforms Listing
**Classification:** LISTING
**Source:** Nuclei Template (`wp-arforms-listing.yaml`)

## Description
Searches for sensitive directories present in the arforms plugin.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/arforms/
```

