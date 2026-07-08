# Vulnerability: Cisco Web UI Login - Detect
**Classification:** WEBUI
**Source:** Nuclei Template (`cisco-webui-login.yaml`)

## Description
Detects the presence of Cisco Web UI login panels

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/webui/
```

