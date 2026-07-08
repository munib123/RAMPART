# Vulnerability: Xiaomi Wireless Router Admin Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`xiaomi-wireless-router-login.yaml`)

## Description
Xiaomi Wireless router admin panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/luci/web
```

