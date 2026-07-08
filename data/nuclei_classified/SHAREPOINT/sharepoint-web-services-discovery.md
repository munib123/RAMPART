# Vulnerability: Microsoft SharePoint - Web Services Discovery
**Classification:** SHAREPOINT
**Source:** Nuclei Template (`sharepoint-web-services-discovery.yaml`)

## Description
Detected exposed SharePoint web services via /_vti_bin/spdisco.aspx endpoint

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_vti_bin/spdisco.aspx
```

