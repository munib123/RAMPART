# Vulnerability: EasyCVR Video Management - Arbitrary File Read
**Classification:** EASYCVR
**Source:** Nuclei Template (`easycvr-arbitrary-file-read.yaml`)

## Description
The EasyCVR-video management platform taillog interface has an arbitrary file read vulnerability. Unauthenticated attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., which puts the website in an extremely insecure state.

## Secure Mitigation
Ensure that the application does not allow directory traversal or access to sensitive files through web requests. Implement proper input validation and restrict access to critical files.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

GET /taillog/oxsecl/..\easycvr.ini HTTP/1.1
Host: {{Hostname}}
```

