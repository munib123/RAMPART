# Vulnerability: WordPress gtranslate Plugin Directory Listing
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wordpress-gtranslate-plugin-listing.yaml`)

## Description
Searches for sensitive directories present in the gtranslate wordpress plugin.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/gtranslate/
```

