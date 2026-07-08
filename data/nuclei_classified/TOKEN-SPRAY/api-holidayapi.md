# Vulnerability: Holiday API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-holidayapi.yaml`)

## Description
Historical data regarding holidays

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://holidayapi.com/v1/holidays?pretty&key={{token}}&country=US&year=2020&language=EN
```

