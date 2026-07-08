# Vulnerability: Microsoft SharePoint - Layouts Disclosure
**Classification:** SHAREPOINT
**Source:** Nuclei Template (`sharepoint-layouts-disclosure.yaml`)

## Description
Detected exposed SharePoint Layouts endpoints.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_layouts/15/viewlsts.aspx
GET {{BaseURL}}/_layouts/viewlsts.aspx
```

