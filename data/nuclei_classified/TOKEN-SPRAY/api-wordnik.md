# Vulnerability: Wordnik API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-wordnik.yaml`)

## Description
Dictionary Data

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.wordnik.com/v4/word.json/hedgehog/topExample?useCanonical=false&api_key={{token}}
```

