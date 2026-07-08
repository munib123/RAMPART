# Vulnerability: Socks5 VPN - Sensitive File Disclosure
**Classification:** ESOCKS5
**Source:** Nuclei Template (`socks5-vpn-config.yaml`)

## Description
Information Leakage in the Socks5 VPN login system of Wheilton e-Ditong, and the administrator account password can be obtained by visiting a specially crafted URL.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/backup/config.xml
```

