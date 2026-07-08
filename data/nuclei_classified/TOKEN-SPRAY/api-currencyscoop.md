# Vulnerability: CurrencyScoop API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-currencyscoop.yaml`)

## Description
Real-time and historical currency rates JSON API

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.currencyscoop.com/v1/historical?api_key={{token}}&date=2022-01-01
```

