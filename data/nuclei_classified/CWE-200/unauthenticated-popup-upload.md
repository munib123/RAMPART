# Vulnerability: Unauthenticated Popup File Upload - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`unauthenticated-popup-upload.yaml`)

## Description
Endpoints where files can be uploaded without authentication were detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/RichWidgets/Popup_Upload.aspx
```

