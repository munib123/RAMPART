# Vulnerability: Coinlayer API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-coinlayer.yaml`)

## Description
Real-time Crypto Currency Exchange Rates

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.coinlayer.com/live?access_key={{token}}
```

