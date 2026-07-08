# Vulnerability: WordPress Bricks Builder Theme Version
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-bricks-builder-theme.yaml`)

## Description
- Checks for Bricks Builder Theme versions.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/themes/bricks/readme.txt
```

