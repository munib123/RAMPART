# Vulnerability: Ghost CMS Installation Setup - Exposure
**Classification:** GHOST
**Source:** Nuclei Template (`ghost-cms-installer.yaml`)

## Description
Detected Ghost CMS installation setup wizard accessible without authentication. An unauthenticated remote attacker can navigate to
/ghost/#/setup and complete the installation to gain full owner-level administrative control of the site.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ghost/api/admin/authentication/setup/
GET {{BaseURL}}/ghost/api/v3/admin/authentication/setup/
```

