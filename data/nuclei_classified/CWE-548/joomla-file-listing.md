# Vulnerability: Joomla! Database File List
**Classification:** CWE-548
**Source:** Nuclei Template (`joomla-file-listing.yaml`)

## Description
A Joomla! database directory /libraries/joomla/database/ was found exposed and has directory indexing enabled.

## Secure Mitigation
Disable directory indexing on the /libraries/joomla/database/ directory or remove the content from the web root. If the databases can be download, rotate any credentials contained in the databases.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/libraries/joomla/database/
```

