# Vulnerability: Adobe ColdFusion CFIDE - Directory Listing
**Classification:** CWE-548
**Source:** Nuclei Template (`coldfusion-cfide-dir-listing.yaml`)

## Description
Detected Adobe ColdFusion CFIDE directory listing was exposed. This can reveal sensitive files and subdirectories including administrator interfaces, scripts, and application components.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/CFIDE/
```

