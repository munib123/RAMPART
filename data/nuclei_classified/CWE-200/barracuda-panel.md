# Vulnerability: Barracuda SSL VPN Log In
**Classification:** CWE-200
**Source:** Nuclei Template (`barracuda-panel.yaml`)

## Description
The Barracuda SSL VPN is an integrated hardware and software solution enabling secure, clientless remote access to internal network resources from any web browser.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/default/showLogon.do
```

