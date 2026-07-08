# Vulnerability: EasyCVR User - Information Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`easycvr-user-info-disclosure.yaml`)

## Description
The EasyCVR Video Management Platform is vulnerable to user information leakage. This template checks for exposed user information through the endpoint `/api/v1/userlist?pageindex=0&pagesize=10`.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/v1/userlist?pageindex=0&pagesize=10
```

