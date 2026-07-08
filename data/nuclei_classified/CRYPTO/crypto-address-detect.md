# Vulnerability: Exposed Cryptocurrency Wallet Address
**Classification:** CRYPTO
**Source:** Nuclei Template (`crypto-address-detect.yaml`)

## Description
Detected Bitcoin, Monero, Ethereum, or XRP wallet addresses were identified in webpage content.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

