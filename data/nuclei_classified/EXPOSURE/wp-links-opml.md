# Vulnerability: WordPress wp-links-opml.php - Version Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`wp-links-opml.yaml`)

## Description
WordPress wp-links-opml.php file was publicly accessible and expossed the WordPress version in the generator tag.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-links-opml.php
```

