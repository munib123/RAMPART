# Vulnerability: WordPress Plugin SG Optimizer - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-sg-cachepress-fpd.yaml`)

## Description
WordPress Plugin SG Optimizer Plugin files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/sg-cachepress/core/File_Cacher/File_Cacher.php
```

