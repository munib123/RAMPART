# Vulnerability: Pulse Secure VPN Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`pulse-secure-panel.yaml`)

## Description
Pulse Secure VPN login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/dana-na/auth/url_default/welcome.cgi
GET {{BaseURL}}/dana-na/auth/url_2/welcome.cgi
GET {{BaseURL}}/dana-na/auth/url_3/welcome.cgi
```

