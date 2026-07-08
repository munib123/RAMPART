# Vulnerability: Laravel Sanctum - Stateful Domain CSRF Misconfiguration
**Classification:** LARAVEL
**Source:** Nuclei Template (`laravel-sanctum-misconfig.yaml`)

## Description
Laravel Sanctum's SPA authentication uses cookie-based session authentication for first-party single-page applications. The /sanctum/csrf-cookie endpoint issues XSRF-TOKEN cookies to requesting origins. When SANCTUM_STATEFUL_DOMAINS is misconfigured with wildcard or overly permissive values, the application responds with CORS headers that permit arbitrary external origins to make credentialed cross-origin requests.

## Secure Mitigation
Restrict SANCTUM_STATEFUL_DOMAINS and SESSION_DOMAIN to only trusted application domains, and configure session cookies with SameSite=Lax or SameSite=Strict to reduce unauthorized cross-site requests. Additionally, ensure config/cors.php does not use wildcard (*) origins when supports_credentials is enabled, allowing only trusted origins for credentialed requests.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /sanctum/csrf-cookie HTTP/1.1
Host: {{Hostname}}
Origin: https://evil.oast.pro
Referer: https://evil.oast.pro
```

