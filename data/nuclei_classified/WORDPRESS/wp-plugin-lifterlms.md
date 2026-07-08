# Vulnerability: WordPress Plugin lifterlms Listing
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-plugin-lifterlms.yaml`)

## Description
Searches for sensitive directories present in the lifterlms plugin.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/lifterlms/
```

