# Vulnerability: BitcoinAverage API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-bitcoinaverage.yaml`)

## Description
Digital Asset Price Data for the blockchain industry

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://apiv2.bitcoinaverage.com/exchanges/ticker/bitstamp HTTP/1.1
Host: apiv2.bitcoinaverage.com
x-ba-key: {{token}}
```

