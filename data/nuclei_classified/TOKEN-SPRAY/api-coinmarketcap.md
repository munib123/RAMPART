# Vulnerability: CoinMarketCap API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-coinmarketcap.yaml`)

## Description
Cryptocurrencies Prices

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://pro-api.coinmarketcap.com/v1/cryptocurrency/listings/latest HTTP/1.1
Host: pro-api.coinmarketcap.com
X-CMC_PRO_API_KEY: {{token}}
```

