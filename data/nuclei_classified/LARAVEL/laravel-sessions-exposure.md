# Vulnerability: Laravel Sessions Folder Exposure
**Classification:** LARAVEL
**Source:** Nuclei Template (`laravel-sessions-exposure.yaml`)

## Description
Detected unauthenticated access to the Laravel session storage directory, allowing attackers to browse and download session files that may contain active authentication tokens, CSRF tokens, and serialized user data.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/storage/framework/sessions/
GET {{BaseURL}}/storage/sessions/
```

