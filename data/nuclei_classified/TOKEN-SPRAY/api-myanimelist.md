# Vulnerability: MyAnimeList API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-myanimelist.yaml`)

## Description
Anime and Manga Database and Community

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.myanimelist.net/v2/anime?q=one&limit=4
```

