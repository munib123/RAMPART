# Vulnerability: SavePage API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-savepage.yaml`)

## Description
A free, RESTful API used to screenshot any desktop, or mobile website

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.savepage.io/v1?key={{token}}&q=https://selfcontained.test
```

