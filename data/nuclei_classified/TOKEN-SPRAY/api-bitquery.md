# Vulnerability: Bitquery API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-bitquery.yaml`)

## Description
Onchain GraphQL APIs & DEX APIs

## Vulnerable Code Pattern / Exploit Payload
```http
POST https://graphql.bitquery.io HTTP/1.1
Host: graphql.bitquery.io
X-API-KEY: {{token}}
```

