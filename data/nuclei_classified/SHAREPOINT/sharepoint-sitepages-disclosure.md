# Vulnerability: Microsoft SharePoint - Site Pages Disclosure
**Classification:** SHAREPOINT
**Source:** Nuclei Template (`sharepoint-sitepages-disclosure.yaml`)

## Description
Microsoft SharePoint Site Pages library (/SitePages/) is accessible without proper authentication, exposing site content, page structure, and potentially sensitive information. The Site Pages library contains modern SharePoint pages (.aspx files)

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/SitePages/Forms/AllPages.aspx
```

