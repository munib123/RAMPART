# Vulnerability: Application Setting file disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`appsettings-file-disclosure.yaml`)

## Description
appsetting.json file discloses the DB connection strings containing sensitive information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/appsettings.json
GET {{BaseURL}}/appsettings.Production.json
```

