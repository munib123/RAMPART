# Vulnerability: Hirak Exchange Rates API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-hirak-rates.yaml`)

## Description
Exchange rates between 162 currency & 300 crypto currency update each 5 min, accurate, no limits

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://rates.hirak.site/stat/?token={{token}}
```

