# Vulnerability: Jellyfin Public Users - Exposure
**Classification:** CWE-200,CWE-306
**Source:** Nuclei Template (`jellyfin-public-users-exposure.yaml`)

## Description
The Jellyfin media server exposed user information via the public users API endpoint. This endpoint could have leaked sensitive data including usernames, user IDs, server IDs, administrator status, password configuration, login activity, and user policies without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Users/Public
GET {{BaseURL}}/jellyfin/Users/Public
```

