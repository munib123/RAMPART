# Vulnerability: Abstract Api Exchange Rates Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-abstract-exchange-rates.yaml`)

## Description
Get live and historical data from 60+ fiat and crypto currencies via a modern REST API

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://exchange-rates.abstractapi.com/v1/live/?api_key={{token}}&base=USD
```

