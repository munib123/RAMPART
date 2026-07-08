# Vulnerability: Everything Server Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`everything-listing.yaml`)

## Description
Everything is a freeware desktop search utility for Windows that can rapidly find files and folders by name.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

