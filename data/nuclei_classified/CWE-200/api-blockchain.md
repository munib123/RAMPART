# Vulnerability: Blockchain API Test
**Classification:** CWE-200
**Source:** Nuclei Template (`api-blockchain.yaml`)

## Description
Bitcoin Payment, Wallet & Transaction Data

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.blockchain.com/v3/exchange/accounts HTTP/1.1
Host: api.blockchain.com
X-API-Token: {{token}}
```

