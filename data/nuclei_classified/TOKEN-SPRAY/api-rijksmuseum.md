# Vulnerability: Rijksmuseum API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-rijksmuseum.yaml`)

## Description
The Rijksmuseum is a Dutch national museum dedicated to arts and history in Amsterdam

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.rijksmuseum.nl/api/nl/usersets?key={{token}}&format=json&page=2
```

