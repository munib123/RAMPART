# Vulnerability: Brave New Coin API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-bravenewcoin.yaml`)

## Description
Real-time and historic crypto data from more than 200+ exchanges

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://bravenewcoin.p.rapidapi.com/market HTTP/1.1
X-Rapidapi-Host: bravenewcoin.p.rapidapi.com
X-Rapidapi-Key: {{token}}
Host: bravenewcoin.p.rapidapi.com
```

