# Vulnerability: MOBOTIX Guest Camera Live View - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mobotix-guest-camera.yaml`)

## Description
MOBOTIX Guest Camera live view was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/guestimage.html
```

