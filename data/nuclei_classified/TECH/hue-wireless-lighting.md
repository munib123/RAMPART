# Vulnerability: Hue Personal Wireless Lighting - Detect
**Classification:** TECH
**Source:** Nuclei Template (`hue-wireless-lighting.yaml`)

## Description
This template detects the presence of Hue Personal Wireless Lighting systems by looking for specific welcome messages in the response.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

