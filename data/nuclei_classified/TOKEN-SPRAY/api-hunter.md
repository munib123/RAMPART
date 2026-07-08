# Vulnerability: Hunter API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-hunter.yaml`)

## Description
API for domain search, professional email finder, author finder and email verifier

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.hunter.io/v2/domain-search?domain=stripe.com&api_key={{token}}
```

