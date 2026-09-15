# Nuclei Template: Laravel Sanctum - Stateful Domain CSRF Misconfiguration
**Template ID:** laravel-sanctum-misconfig
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**Severity:** Medium
**Source:** Nuclei Template (`laravel-sanctum-misconfig.yaml`)

## Vulnerability Information & PoC

## Description
Laravel Sanctum's SPA authentication uses cookie-based session authentication for first-party single-page applications. The /sanctum/csrf-cookie endpoint issues XSRF-TOKEN cookies to requesting origins. When SANCTUM_STATEFUL_DOMAINS is misconfigured with wildcard or overly permissive values, the application responds with CORS headers that permit arbitrary external origins to make credentialed cross-origin requests.

## Impact
An attacker can host a malicious page that performs authenticated actions on behalf of any logged-in user who visits it. Exploitable actions include reading sensitive user data, modifying account settings, changing email or password, initiating transactions, or any other operation exposed by Sanctum-protected API endpoints. The attack requires no prior authentication and only needs the victim to visit an attacker-controlled URL while logged in.

## Steps to reproduce / Exploit Payload
```http
GET /sanctum/csrf-cookie HTTP/1.1
Host: {{Hostname}}
Origin: https://evil.oast.pro
Referer: https://evil.oast.pro
```

## Remediation
Restrict SANCTUM_STATEFUL_DOMAINS and SESSION_DOMAIN to only trusted application domains, and configure session cookies with SameSite=Lax or SameSite=Strict to reduce unauthorized cross-site requests. Additionally, ensure config/cors.php does not use wildcard (*) origins when supports_credentials is enabled, allowing only trusted origins for credentialed requests.

## References
- https://laravel.com/docs/11.x/sanctum#spa-authentication
- https://laravel.com/docs/11.x/sanctum#cors-and-cookies
