# Vulnerability: Wavlink Panel - Unauthenticated Access
**Classification:** EXPOSURE
**Source:** Nuclei Template (`unauth-wavink-panel.yaml`)

## Description
Wavlink Panel was able to be accessed with no authentication requirements in place.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wifi_base.shtml
```

