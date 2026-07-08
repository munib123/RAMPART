# Vulnerability: Microsoft SharePoint - Site Metadata Disclosure
**Classification:** SHAREPOINT
**Source:** Nuclei Template (`sharepoint-site-metadata-disclosure.yaml`)

## Description
Detected exposed SharePoint site metadata endpoints.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_api/site
GET {{BaseURL}}/_api/web
```

