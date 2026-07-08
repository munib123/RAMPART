# Vulnerability: IUCN API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-iucn.yaml`)

## Description
IUCN Red List of Threatened Species

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://apiv3.iucnredlist.org/api/v3/country/list?token={{token}}
```

