# Vulnerability: HortonWorks SmartSense Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`smartsense-default-login.yaml`)

## Description
HortonWorks SmartSense default admin login information was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /apt/v1/context HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ':' + password)}}
```

