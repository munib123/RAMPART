# Vulnerability: Detect Telerik Web UI Fileupload Handler
**Classification:** TECH
**Source:** Nuclei Template (`telerik-fileupload-detect.yaml`)

## Description
This template detects the Telerik Web UI fileupload handler.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Telerik.Web.UI.WebResource.axd?type=rau
```

