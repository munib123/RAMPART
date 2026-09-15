# Nuclei Template: Jellyfin Public Users - Exposure
**Template ID:** jellyfin-public-users-exposure
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`jellyfin-public-users-exposure.yaml`)

## Vulnerability Information & PoC

## Description
The Jellyfin media server exposed user information via the public users API endpoint. This endpoint could have leaked sensitive data including usernames, user IDs, server IDs, administrator status, password configuration, login activity, and user policies without authentication.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/Users/Public
GET {{BaseURL}}/jellyfin/Users/Public
```

## References
- https://github.com/jellyfin/jellyfin/issues/880
- https://jellyfin.org/docs/
