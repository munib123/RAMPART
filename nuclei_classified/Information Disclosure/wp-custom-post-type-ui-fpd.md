# Nuclei Template: WordPress Custom Post Type UI - Full Path Disclosure
**Template ID:** wp-custom-post-type-ui-fpd
**Vulnerability Class:** Information Disclosure
**Severity:** Low
**CWE:** CWE-200
**Source:** Nuclei Template (`wp-custom-post-type-ui-fpd.yaml`)

## Vulnerability Information & PoC

## Description
Detected WordPress Custom Post Type UI exposes internal file system path through direct file access.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/custom-post-type-ui/custom-post-type-ui.php
```

## References
- https://wordpress.org/plugins/custom-post-type-ui/
- https://github.com/WebDevStudios/custom-post-type-ui
