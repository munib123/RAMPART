# Vulnerability: Laravel Passport - OAuth2 Keys Exposed
**Classification:** LARAVEL
**Source:** Nuclei Template (`laravel-passport-keys-exposed.yaml`)

## Description
Laravel Passport OAuth2 RSA private or public keys are publicly accessible at default storage paths. Exposed private keys allow attackers to forge OAuth2 access tokens and impersonate any user.

## Secure Mitigation
Ensure the storage directory is not publicly accessible. Move Passport keys outside the web root or configure the web server to deny access to the storage directory.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/storage/oauth-private.key
GET {{BaseURL}}/storage/oauth-public.key
```

