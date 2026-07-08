# Vulnerability: Bluesky User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`bluesky.yaml`)

## Description
Bluesky user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://bsky.app/profile/{{user}}.bsky.social
```

