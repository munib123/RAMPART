# Vulnerability: AXIS Network Camera Live View - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`liveview-axis-camera.yaml`)

## Description
AXIS Network Camera live view was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/view/viewer_index.shtml
GET {{BaseURL}}/pics/logo_70x29px.gif
```

