# Vulnerability: Opentwrt luCI - Admin Login Page
**Classification:** PANEL
**Source:** Nuclei Template (`openwrt-luci-panel.yaml`)

## Description
An Opentwrt admin login page was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/luci
```

