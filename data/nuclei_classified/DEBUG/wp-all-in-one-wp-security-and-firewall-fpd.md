# Vulnerability: All In One WP Security & Firewall - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-all-in-one-wp-security-and-firewall-fpd.yaml`)

## Description
All In One WP Security & Firewall WordPress plugin contains a full path disclosure vulnerability due to improper access restrictions in its source files, allowing unauthenticated attackers to retrieve full server paths and aiding exploitation.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/all-in-one-wp-security-and-firewall/wp-security-core.php
```

