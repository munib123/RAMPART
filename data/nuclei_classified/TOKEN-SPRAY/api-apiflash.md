# Vulnerability: ApiFlash API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-apiflash.yaml`)

## Description
Chrome based screenshot API for developers

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.apiflash.com/v1/urltoimage?access_key={{token}}&url=https://selfcontained.test
```

