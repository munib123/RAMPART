# Vulnerability: Typo3 Directory Listing
**Classification:** TYPO3
**Source:** Nuclei Template (`typo3-directory-listing.yaml`)

## Description
Detects directory listing enabled on the TYPO3 temp directory. The typo3temp folder contains cached files, compiled assets, and temporary data that may reveal sensitive information about the application structure and configuration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

GET {{BaseURL}}/typo3temp/
```

