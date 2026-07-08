# Vulnerability: Postman Collection Exposure
**Classification:** CWE-538
**Source:** Nuclei Template (`postman-collection-exposure.yaml`)

## Description
Detected exposed Postman collection JSON files that contained API endpoints and environment details. These files were publicly accessible and disclosed authentication headers and other sensitive information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/postman.json
GET {{BaseURL}}/docs/postman.json
GET {{BaseURL}}/api/postman.json
GET {{BaseURL}}/postman_collection.json
GET {{BaseURL}}/collections/postman.json
```

