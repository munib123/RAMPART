# Nuclei Template: Laravel Pulse - Unauthenticated Dashboard Access
**Template ID:** laravel-pulse-unauth
**Vulnerability Class:** Missing Authentication for Critical Function
**Severity:** Medium
**CWE:** CWE-306
**Source:** Nuclei Template (`laravel-pulse-unauth.yaml`)

## Vulnerability Information & PoC

## Description
Laravel Pulse monitoring dashboard is accessible without authentication. Pulse displays server performance metrics, slow queries, user activity, cache hit rates, and exception logs that could aid attackers in reconnaissance.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/pulse
```

## Remediation
Configure Pulse's gate method in the PulseServiceProvider to restrict access. Add proper authorization checks using Gate::define in app/Providers/PulseServiceProvider.php.

## References
- https://laravel.com/docs/11.x/pulse#dashboard-authorization
- https://owasp.org/Top10/A01_2021-Broken_Access_Control/
