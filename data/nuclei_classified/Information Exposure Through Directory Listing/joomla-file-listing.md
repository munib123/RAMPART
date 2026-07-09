# Nuclei Template: Joomla! Database File List
**Template ID:** joomla-file-listing
**Vulnerability Class:** Information Exposure Through Directory Listing
**Severity:** Medium
**CWE:** CWE-548
**Source:** Nuclei Template (`joomla-file-listing.yaml`)

## Vulnerability Information & PoC

## Description
A Joomla! database directory /libraries/joomla/database/ was found exposed and has directory indexing enabled.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/libraries/joomla/database/
```

## Remediation
Disable directory indexing on the /libraries/joomla/database/ directory or remove the content from the web root. If the databases can be download, rotate any credentials contained in the databases.

## References
- https://www.exploit-db.com/ghdb/6377
