# Vulnerability: Microsoft SharePoint Files Disclosure
**Classification:** SHAREPOINT
**Source:** Nuclei Template (`sharepoint-files-disclosure.yaml`)

## Description
Deteted information revealed that Microsoft SharePoint files had been inadvertently disclosed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_api/web/roledefinitions
```

