# Vulnerability: WordPress ManageWP Worker - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-worker-fpd.yaml`)

## Description
WordPress ManageWP Worker plugin files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/worker/src/MMB/User.php
```

