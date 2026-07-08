# Vulnerability: Laravel Clockwork - Sensitive Information Exposure
**Classification:** LARAVEL
**Source:** Nuclei Template (`laravel-clockwork-exposure.yaml`)

## Description
Laravel Clockwork (itsgoingd/clockwork) was detected as enabled and publicly accessible. When left active in production, it exposes SQL queries, request data, session variables, mail logs, and application internals to any visitor.

## Secure Mitigation
Disable Clockwork in production by setting CLOCKWORK_ENABLE=false in the .env file or removing the package from production dependencies.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/__clockwork
```

