# Vulnerability: Umbraco CMS - Directory Listing Exposure
**Classification:** CWE-548
**Source:** Nuclei Template (`umbraco-directory-listing.yaml`)

## Description
Detected directory listing enabled on sensitive Umbraco CMS directories, potentially exposing configuration files, logs, backups, and other sensitive data.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/App_Data/
GET {{BaseURL}}/App_Plugins/
```

