# Vulnerability: Directory Listing Enabled
**Classification:** MISC
**Source:** Nuclei Template (`directory-listing.yaml`)

## Description
Directory Indexing is a web server feature that allows the contents of a directory to be displayed when no index file is present. This can be a security risk as it can expose sensitive files, old backup or unreferenced files.

## Secure Mitigation
Disable directory listing in the web server configuration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}{{path_to_check}}
```

