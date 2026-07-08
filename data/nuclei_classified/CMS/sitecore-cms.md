# Vulnerability: Sitecore CMS - Detect
**Classification:** CMS
**Source:** Nuclei Template (`sitecore-cms.yaml`)

## Description
Detect Sitecore Content Management System (CMS) websites based on a redirect from the sitecore media handler URL pattern to the notfound.aspx page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/-/media/doo-doo.ashx
```

