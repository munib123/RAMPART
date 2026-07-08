# Vulnerability: Festivo API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-festivo.yaml`)

## Description
Fastest and most advanced public holiday and observance service on the market

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.getfestivo.com/v2/holidays?country=US&api_key={{token}}&year=2020
```

