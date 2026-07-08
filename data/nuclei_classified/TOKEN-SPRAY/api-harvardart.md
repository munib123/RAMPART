# Vulnerability: Harvard Art Museums API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-harvardart.yaml`)

## Description
Harvard Art

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.harvardartmuseums.org/color/34838442?apikey={{token}}
```

