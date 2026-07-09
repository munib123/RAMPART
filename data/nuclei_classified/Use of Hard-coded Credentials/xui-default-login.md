# Nuclei Template: X-UI - Default Login
**Template ID:** xui-default-login
**Vulnerability Class:** Use of Hard-coded Credentials
**Severity:** High
**CWE:** CWE-798
**Source:** Nuclei Template (`xui-default-login.yaml`)

## Vulnerability Information & PoC

## Description
X-UI contains default credentials. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/login
POST {{BaseURL}}/login
```

## References
- https://github.com/vaxilu/x-ui
- https://seakfind.github.io/2021/10/10/X-UI/#:~:text=By%20default%2C%20the%20login%20user,the%20password%20is%20also%20admin%20.
