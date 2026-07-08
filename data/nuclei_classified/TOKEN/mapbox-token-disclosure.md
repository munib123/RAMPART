# Vulnerability: Mapbox Token Disclosure
**Classification:** TOKEN
**Source:** Nuclei Template (`mapbox-token-disclosure.yaml`)

## Description
Mapbox secret token is exposed to external users.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
@Host: https://api.mapbox.com:443
GET /geocoding/v5/mapbox.places/Los%20Angeles.json?access_token={{token}} HTTP/1.1
Host: api.mapbox.com
```

