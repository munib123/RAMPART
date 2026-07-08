# Vulnerability: Beaver Builder Page Builder - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-beaver-builder-lite-version-fpd.yaml`)

## Description
Beaver Builder Page Builder WordPress plugin contains a full path disclosure vulnerability due to improper access restrictions in its source files, allowing unauthenticated attackers to retrieve full server paths and aiding exploitation.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/beaver-builder-lite-version/fl-builder.php
```

