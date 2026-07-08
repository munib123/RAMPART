# Vulnerability: IP Webcam Viewer Page - Detect
**Classification:** WEBCAM
**Source:** Nuclei Template (`ip-webcam.yaml`)

## Description
Searches for exposed webcams by querying the  endpoint and the existence of IP Webcam in the body.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

