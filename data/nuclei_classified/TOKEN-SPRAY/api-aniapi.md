# Vulnerability: AniAPI API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-aniapi.yaml`)

## Description
Anime discovery, streaming & syncing with trackers

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.aniapi.com/v1/auth/me
```

