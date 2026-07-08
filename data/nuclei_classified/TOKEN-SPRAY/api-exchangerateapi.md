# Vulnerability: ExchangeRate-API API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-exchangerateapi.yaml`)

## Description
Free currency conversion

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://v6.exchangerate-api.com/v6/{{token}}/latest/USD
```

