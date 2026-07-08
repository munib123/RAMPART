# Vulnerability: Laravel log file publicly accessible
**Classification:** LARAVEL
**Source:** Nuclei Template (`laravel-log-file.yaml`)

## Description
The log file of this Laravel web app might reveal details on the inner workings of the app, possibly even tokens, credentials or personal information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/storage/logs/laravel.log
```

