# Vulnerability: WordPress Elementor Plugin Directory Listing
**Classification:** LISTING
**Source:** Nuclei Template (`wordpress-elementor-plugin-listing.yaml`)

## Description
Searches for sensitive directories present in the elementor wordpress plugin.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/elementor/
```

