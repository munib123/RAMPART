# Vulnerability: Bsky User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`bsky.yaml`)

## Description
Bsky user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://bsky.app/profile/{{user}}.bsky.social
```

