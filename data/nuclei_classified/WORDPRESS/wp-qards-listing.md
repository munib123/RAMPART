# Vulnerability: WordPress Plugin Qards
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-qards-listing.yaml`)

## Description
Searches for sensitive directories present in the qards plugin.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/qards/
```

