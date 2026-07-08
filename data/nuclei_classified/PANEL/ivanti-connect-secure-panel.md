# Vulnerability: Ivanti Connect Secure Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`ivanti-connect-secure-panel.yaml`)

## Description
Ivanti Connect Secure provides a seamless, cost-effective SSL VPN solution for remote and mobile users from any web-enabled device to corporate resources— anytime, anywhere.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/dana-na/auth/url_default/welcome.cgi
```

