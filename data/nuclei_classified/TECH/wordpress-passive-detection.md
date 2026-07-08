# Vulnerability: WordPress Passive Detection - Plugins & Themes
**Classification:** TECH
**Source:** Nuclei Template (`wordpress-passive-detection.yaml`)

## Description
Passively enumerates WordPress plugins and themes through REST API discovery and HTML source analysis without brute-forcing, based on wpprobe methodology.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?rest_route=/
GET {{BaseURL}}/wp-json/
GET {{BaseURL}}
```

