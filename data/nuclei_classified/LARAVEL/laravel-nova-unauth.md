# Vulnerability: Laravel Nova - Unauthenticated Admin Panel Access
**Classification:** LARAVEL
**Source:** Nuclei Template (`laravel-nova-unauth.yaml`)

## Description
Laravel Nova admin panel is accessible without authentication. Nova provides full CRUD access to application models and database records, making unauthenticated access a critical security risk.

## Secure Mitigation
Configure Nova's gate method in the NovaServiceProvider to restrict access. Ensure the Gate::define callback in app/Providers/NovaServiceProvider.php properly validates user authorization.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/nova/dashboards/main
GET {{BaseURL}}/nova/resources
```

