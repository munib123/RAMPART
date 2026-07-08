# Vulnerability: Microsoft SharePoint - Master Page Disclosure
**Classification:** SHAREPOINT
**Source:** Nuclei Template (`sharepoint-masterpage-disclosure.yaml`)

## Description
Detected exposed SharePoint Master Page endpoints.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_catalogs/masterpage/Forms/AllItems.aspx
GET {{BaseURL}}/_catalogs/15/masterpage/Forms/AllItems.aspx
```

