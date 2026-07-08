# Vulnerability: Datadog Login Check
**Classification:** CLOUD
**Source:** Nuclei Template (`datadog-login-check.yaml`)

## Description
Checks for a valid datadog account.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://app.datadoghq.com/account/login HTTP/1.1
Host: app.datadoghq.com

POST https://app.datadoghq.com/account/login? HTTP/1.1
Host: app.datadoghq.com
Content-Type: application/x-www-form-urlencoded

_authentication_token={{auth_token}}&username={{username}}&password={{password}}
```

