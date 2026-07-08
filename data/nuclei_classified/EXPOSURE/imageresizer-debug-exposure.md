# Vulnerability: ImageResizer Debug - Information Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`imageresizer-debug-exposure.yaml`)

## Description
The ImageResizer debug endpoint exposes sensitive server configuration and path information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/resizer.debug.ashx
GET {{BaseURL}}/resizer.debug
```

