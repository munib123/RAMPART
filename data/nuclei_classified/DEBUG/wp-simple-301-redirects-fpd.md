# Vulnerability: Simple 301 Redirects - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-simple-301-redirects-fpd.yaml`)

## Description
Simple 301 Redirects  WordPress plugin contains a full path disclosure vulnerability due to improper access restrictions in its source files, allowing unauthenticated attackers to retrieve full server paths and aiding exploitation.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/plugins/simple-301-redirects/wp-simple-301-redirects.php
```

