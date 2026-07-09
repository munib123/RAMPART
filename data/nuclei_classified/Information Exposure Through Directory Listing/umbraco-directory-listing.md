# Nuclei Template: Umbraco CMS - Directory Listing Exposure
**Template ID:** umbraco-directory-listing
**Vulnerability Class:** Information Exposure Through Directory Listing
**Severity:** Medium
**CWE:** CWE-548
**Source:** Nuclei Template (`umbraco-directory-listing.yaml`)

## Vulnerability Information & PoC

## Description
Detected directory listing enabled on sensitive Umbraco CMS directories, potentially exposing configuration files, logs, backups, and other sensitive data.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/App_Data/
GET {{BaseURL}}/App_Plugins/
```

## References
- https://docs.umbraco.com/umbraco-cms/reference/security/security-hardening
