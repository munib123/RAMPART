# Vulnerability: Microsoft SharePoint Detect
**Classification:** SHAREPOINT
**Source:** Nuclei Template (`microsoft-sharepoint-detect.yaml`)

## Description
Check for SharePoint, using HTTP header MicrosoftSharePointTeamServices

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

