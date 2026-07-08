# Vulnerability: OpenConnect VPN Server (ocserv) - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`ocserv-panel.yaml`)

## Description
OpenConnect VPN Server (ocserv) is an open-source VPN server compatible with
Cisco AnyConnect clients. It uses DTLS and TLS for secure connectivity and
is commonly exposed on port 443 or 4443. The server header can expose
OpenConnect or ocserv-specific markers.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

