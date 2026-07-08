# Vulnerability: Laravel Pulse - Unauthenticated Dashboard Access
**Classification:** CWE-306
**Source:** Nuclei Template (`laravel-pulse-unauth.yaml`)

## Description
Laravel Pulse monitoring dashboard is accessible without authentication. Pulse displays server performance metrics, slow queries, user activity, cache hit rates, and exception logs that could aid attackers in reconnaissance.

## Secure Mitigation
Configure Pulse's gate method in the PulseServiceProvider to restrict access. Add proper authorization checks using Gate::define in app/Providers/PulseServiceProvider.php.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/pulse
```

