# Vulnerability: Laravel Debugbar - Sensitive Information Exposure
**Classification:** LARAVEL
**Source:** Nuclei Template (`laravel-debugbar-exposure.yaml`)

## Description
Laravel Debugbar (barryvdh/laravel-debugbar) was detected as enabled and publicly accessible. When left active in production, it exposes SQL queries, request data, session variables, mail logs, and application internals to any visitor.

## Secure Mitigation
Disable Laravel Debugbar in production by setting DEBUGBAR_ENABLED=false in the .env file or removing the package from production dependencies.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_debugbar/open
```

