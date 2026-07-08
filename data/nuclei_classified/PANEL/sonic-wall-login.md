# Vulnerability: SonicWall Network Security Login - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`sonic-wall-login.yaml`)

## Description
SonicWall Network Security Login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/sonicui/7/login/
```

