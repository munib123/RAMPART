# Vulnerability: WordPress Custom Post Type UI - Full Path Disclosure
**Classification:** CWE-200
**Source:** Nuclei Template (`wp-custom-post-type-ui-fpd.yaml`)

## Description
Detected WordPress Custom Post Type UI exposes internal file system path through direct file access.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/custom-post-type-ui/custom-post-type-ui.php
```

