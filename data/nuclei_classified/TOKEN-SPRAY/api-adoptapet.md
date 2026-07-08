# Vulnerability: AdoptAPet API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-adoptapet.yaml`)

## Description
Resource to help get pets adopted

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.adoptapet.com/search/pets_at_shelter?key={{token}}&v=2&output=json&shelter_id=79570&start_number=1&end_number=500
```

