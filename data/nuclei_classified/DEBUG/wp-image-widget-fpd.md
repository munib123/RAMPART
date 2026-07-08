# Vulnerability: Image Widget - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-image-widget-fpd.yaml`)

## Description
Image Widget WordPress plugin contains a full path disclosure vulnerability due to improper access restrictions in its source files, allowing unauthenticated attackers to retrieve full server paths and aiding exploitation.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/plugins/image-widget/image-widget.php
```

