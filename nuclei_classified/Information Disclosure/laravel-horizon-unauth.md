# Nuclei Template: Laravel Horizon Dashboard - Unauthenticated
**Template ID:** laravel-horizon-unauth
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`laravel-horizon-unauth.yaml`)

## Vulnerability Information & PoC

## Description
Laravel Horizon Dashboard unauthenticated was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/api/stats
GET {{BaseURL}}/horizon/api/stats
```

## Remediation
- Configure Authentication in Laravel Horizon.

## References
- https://github.com/laravel/horizon
- https://laravel.com/docs/10.x/horizon#dashboard-authorization
