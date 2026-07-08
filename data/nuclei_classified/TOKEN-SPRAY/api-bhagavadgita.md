# Vulnerability: Bhagavad Gita API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-bhagavadgita.yaml`)

## Description
Open Source Shrimad Bhagavad Gita API including 21+ authors translation in Sanskrit/English/Hindi

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://bhagavadgitaapi.in/slok?api_key={{token}}
```

