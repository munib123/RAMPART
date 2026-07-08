# Vulnerability: Amdoren API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-amdoren.yaml`)

## Description
Free currency API with over 150 currencies

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.amdoren.com/api/currency.php?api_key={{token}}&from=USD&to=EUR
```

