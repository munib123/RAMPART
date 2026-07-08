# Vulnerability: ASP.NET Launch Settings - Exposure
**Classification:** ASPNET
**Source:** Nuclei Template (`aspnet-launchsettings-exposure.yaml`)

## Description
Detected exposed launchSettings.json files in ASP.NET Core applications. This file contains environment variables and launch configurations that may leak sensitive information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Properties/launchSettings.json
GET {{BaseURL}}/launchSettings.json
```

