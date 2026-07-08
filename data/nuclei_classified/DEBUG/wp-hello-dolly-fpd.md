# Vulnerability: WordPress Plugin Hello Dolly - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-hello-dolly-fpd.yaml`)

## Description
WordPress Plugin Hello Dolly plugin files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/hello-dolly/hello.php
```

