# Nuclei Template: GLPI - Directory Listing and Session Exposure
**Template ID:** glpi-directory-listing
**Vulnerability Class:** Information Exposure Through Directory Listing
**Severity:** Medium
**CWE:** CWE-548
**Source:** Nuclei Template (`glpi-directory-listing.yaml`)

## Vulnerability Information & PoC

## Description
Detected GLPI directory listing exposed sensitive files and PHP session data, potentially allowing session hijacking or information disclosure.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/glpi/files/
GET {{BaseURL}}/glpi/files/_sessions/
GET {{BaseURL}}/files/_sessions/
GET {{BaseURL}}/glpi/
```

## References
- https://glpi-project.org/
