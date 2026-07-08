# Vulnerability: Microsoft SharePoint - List API Disclosure
**Classification:** SHAREPOINT
**Source:** Nuclei Template (`sharepoint-lists-api-disclosure.yaml`)

## Description
Detected exposed SharePoint lists-api endpoint without proper authentication, exposing site content and metadata.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_api/web/lists
```

