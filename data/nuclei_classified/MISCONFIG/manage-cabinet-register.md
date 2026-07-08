# Vulnerability: Manage Cabinet Register - Exposed
**Classification:** MISCONFIG
**Source:** Nuclei Template (`manage-cabinet-register.yaml`)

## Description
The path to the Cabinet Storage is omniapp/pages/cabinet/managecabinet.jsf?Action=1. If exposed, it gives an attacker insight into information such as Storage Volume Name, Cabinet Name, it's alias, Deployed AppServer IP Address and Port

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/omniapp/pages/cabinet/managecabinet.jsf?Action=1
```

