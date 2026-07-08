# Vulnerability: Laravel Horizon Dashboard - Unauthenticated
**Classification:** CWE-200
**Source:** Nuclei Template (`laravel-horizon-unauth.yaml`)

## Description
Laravel Horizon Dashboard unauthenticated was detected.

## Secure Mitigation
- Configure Authentication in Laravel Horizon.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/stats
GET {{BaseURL}}/horizon/api/stats
```

