# Vulnerability: Torrent Magnet - Detect
**Classification:** TORRENT
**Source:** Nuclei Template (`torrent-website-detect.yaml`)

## Description
Detects magnet links present on a website, which are commonly used for torrenting.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

