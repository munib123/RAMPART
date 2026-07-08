# Vulnerability: Dell DPI Remote Power Management - Default Login
**Classification:** CWE-798
**Source:** Nuclei Template (`dell-dpi-default-login.yaml`)

## Description
The Dell Metered Rack Power Distribution Unit uses a default username and password which is widely known, and any user could change the default password with access.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /index2.html HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64('{{username}}:{{password}}')}}

POST /index2.html HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64('{{str}}:{{str}}')}}
```

