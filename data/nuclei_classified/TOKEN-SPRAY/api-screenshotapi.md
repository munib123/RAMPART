# Vulnerability: ScreenshotAPI API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-screenshotapi.yaml`)

## Description
Create pixel-perfect website screenshots

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://shot.screenshotapi.net/screenshot?token={{token}}&url=https://example.com
```

