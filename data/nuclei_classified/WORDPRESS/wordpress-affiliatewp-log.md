# Vulnerability: WordPress Plugin "AffiliateWP -- Allowed Products" Log Disclosure
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wordpress-affiliatewp-log.yaml`)

## Description
Exposed debug log in AffiliateWP Wordpress Plugin

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/uploads/affwp-debug.log
```

