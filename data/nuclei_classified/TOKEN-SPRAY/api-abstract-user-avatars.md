# Vulnerability: Abstract Api User Avatars Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-abstract-user-avatars.yaml`)

## Description
Create highly customizable avatar images with a person's name or initials to improve your user experience.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://avatars.abstractapi.com/v1/?api_key={{token}}&name=example
```

