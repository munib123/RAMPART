# Vulnerability: Advanced Custom Fields (ACF) - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-acf-fpd.yaml`)

## Description
Advanced Custom Fields (ACF) for WordPress contains a full path disclosure vulnerability due to improper access restrictions in its source files, allowing unauthenticated attackers to retrieve full server paths and aiding exploitation.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/advanced-custom-fields/includes/fields/class-acf-field-accordion.php
```

