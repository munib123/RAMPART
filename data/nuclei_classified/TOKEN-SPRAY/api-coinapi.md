# Vulnerability: CoinAPI API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-coinapi.yaml`)

## Description
All Currency Exchanges integrate under a single api

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://rest.coinapi.io/v1/exchanges HTTP/1.1
Host: rest.coinapi.io
X-CoinAPI-Key: {{token}}
```

