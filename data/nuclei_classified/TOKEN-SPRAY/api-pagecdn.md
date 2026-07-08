# Vulnerability: PageCDN API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-pagecdn.yaml`)

## Description
Public API for javascript, css and font libraries on PageCDN

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://pagecdn.com/api/v2/private/account/info?apikey={{token}}
```

