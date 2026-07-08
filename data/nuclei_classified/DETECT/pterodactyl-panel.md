# Vulnerability: Pterodactyl game server - Panel
**Classification:** DETECT
**Source:** Nuclei Template (`pterodactyl-panel.yaml`)

## Description
Detects Pterodactyl game server management panel.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/auth/login
```

