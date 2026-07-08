# Vulnerability: Microsoft SharePoint - Exposed Login Endpoint
**Classification:** SHAREPOINT
**Source:** Nuclei Template (`sharepoint-exposed-login-endpoint.yaml`)

## Description
Detected Microsoft SharePoint login and authentication endpoints.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_layouts/15/Authenticate.aspx
GET {{BaseURL}}/_layouts/Authenticate.aspx
```

