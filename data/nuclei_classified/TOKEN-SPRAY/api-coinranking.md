# Vulnerability: Coinranking API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-coinranking.yaml`)

## Description
Live Cryptocurrency data

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.coinranking.com/v2/exchanges HTTP/1.1
Host: api.coinranking.com
x-access-token: {{token}}
```

