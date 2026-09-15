# Nuclei Template: Adobe ColdFusion CFIDE - Directory Listing
**Template ID:** coldfusion-cfide-dir-listing
**Vulnerability Class:** Information Exposure Through Directory Listing
**Severity:** Medium
**CWE:** CWE-548
**Source:** Nuclei Template (`coldfusion-cfide-dir-listing.yaml`)

## Vulnerability Information & PoC

## Description
Detected Adobe ColdFusion CFIDE directory listing was exposed. This can reveal sensitive files and subdirectories including administrator interfaces, scripts, and application components.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/CFIDE/
```

## References
- https://helpx.adobe.com/coldfusion/kb/securing-coldfusion.html
- https://www.carnal0wnage.com/papers/LARES-ColdFusion.pdf
