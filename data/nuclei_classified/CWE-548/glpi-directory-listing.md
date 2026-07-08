# Vulnerability: GLPI - Directory Listing and Session Exposure
**Classification:** CWE-548
**Source:** Nuclei Template (`glpi-directory-listing.yaml`)

## Description
Detected GLPI directory listing exposed sensitive files and PHP session data, potentially allowing session hijacking or information disclosure.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/glpi/files/
GET {{BaseURL}}/glpi/files/_sessions/
GET {{BaseURL}}/files/_sessions/
GET {{BaseURL}}/glpi/
```

