# Vulnerability: ASP.NET Core Development Environment - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`aspnetcore-dev-env.yaml`)

## Description
The ASP.NET Core application is running in Development mode, which could exposes detailed error messages and stack traces on the '/Error' page.

## Secure Mitigation
Set the 'ASPNETCORE_ENVIRONMENT' environment variable to 'Production' and ensure that detailed error messages are not exposed to end-users.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Error
```

