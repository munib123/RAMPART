# Vulnerability: Duplicate Post - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-duplicate-post-fpd.yaml`)

## Description
Duplicate Post WordPress plugin contains a full path disclosure vulnerability due to improper access restrictions in its source files, allowing unauthenticated attackers to retrieve full server paths and aiding exploitation.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/duplicate-post/duplicate-post.php
```

