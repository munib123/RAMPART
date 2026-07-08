# Vulnerability: Etherscan API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-etherscan.yaml`)

## Description
Ethereum explorer API

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.etherscan.io/api?module=account&action=balance&address=0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae&tag=latest&apikey={{token}}
```

