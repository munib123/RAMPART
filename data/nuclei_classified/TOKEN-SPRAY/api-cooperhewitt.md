# Vulnerability: Cooper Hewitt API
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-cooperhewitt.yaml`)

## Description
Smithsonian Design Museum

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.collection.cooperhewitt.org/rest/?method=api.spec.formats&access_token={{token}}
```

