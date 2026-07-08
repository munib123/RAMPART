# Vulnerability: XP Webcam Viewer Page
**Classification:** WEBCAM
**Source:** Nuclei Template (`xp-webcam.yaml`)

## Description
Searches for exposed webcams by querying the /mobile.html endpoint and the existence of webcamXP in the body.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/mobile.html
```

