# Vulnerability: OpenGraphr API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-opengraphr.yaml`)

## Description
Really simple API to retrieve Open Graph data from an URL

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.opengraphr.com/v1/og?api_token={{token}}&url=https://google.com
```

