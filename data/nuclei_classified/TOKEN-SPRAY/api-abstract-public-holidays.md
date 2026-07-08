# Vulnerability: Abstract Api Public Holidays Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-abstract-public-holidays.yaml`)

## Description
Data on national, regional, and religious holidays via API

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://holidays.abstractapi.com/v1/?api_key={{token}}&country=GB&year=2021&month=1&day=25
```

