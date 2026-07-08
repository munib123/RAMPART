# Vulnerability: Wordpress Plugin MStore API
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-mstore-plugin-listing.yaml`)

## Description
Searches for sensitive directories present in the mstore-api plugin.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/mstore-api/
```

