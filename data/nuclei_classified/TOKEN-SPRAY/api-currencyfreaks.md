# Vulnerability: CurrencyFreaks API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-currencyfreaks.yaml`)

## Description
Provides current and historical currency exchange rates with free plan 1K requests/month

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.currencyfreaks.com/latest?apikey={{token}}
```

