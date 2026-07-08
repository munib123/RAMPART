# Vulnerability: serpstack API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-serpstack.yaml`)

## Description
Real-Time & Accurate Google Search Results API

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://api.serpstack.com/search?access_key={{token}}&query=mcdonalds
```

