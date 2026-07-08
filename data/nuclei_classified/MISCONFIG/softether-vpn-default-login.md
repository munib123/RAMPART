# Vulnerability: SoftEther VPN Admin Console - Default Login
**Classification:** MISCONFIG
**Source:** Nuclei Template (`softether-vpn-default-login.yaml`)

## Description
The administrative password for the SoftEther VPN Server is blank.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /admin/default/ HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ':' + password)}}
```

