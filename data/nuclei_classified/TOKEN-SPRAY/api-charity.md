# Vulnerability: Charity Search API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-charity.yaml`)

## Description
Non-profit charity data

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://data.orghunter.com/v1/charitybasic?user_key={{token}}&ein=590774235
```

