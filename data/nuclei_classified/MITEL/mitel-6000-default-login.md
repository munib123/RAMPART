# Vulnerability: Mitel 6000 - Default Login
**Classification:** MITEL
**Source:** Nuclei Template (`mitel-6000-default-login.yaml`)

## Description
This template detects the use of default credentials (admin:22222) on Mitel 6000 devices, which may allow unauthorized access to system information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /sysinfo.html HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64('{{username}}:{{password}}')}}
```

