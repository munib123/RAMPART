# Vulnerability: Currencylayer API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-currencylayer.yaml`)

## Description
Exchange rates and currency conversion

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://api.currencylayer.com/live?access_key={{token}}
```

