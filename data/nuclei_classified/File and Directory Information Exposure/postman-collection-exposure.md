# Nuclei Template: Postman Collection Exposure
**Template ID:** postman-collection-exposure
**Vulnerability Class:** File and Directory Information Exposure
**Severity:** Low
**CWE:** CWE-538
**Source:** Nuclei Template (`postman-collection-exposure.yaml`)

## Vulnerability Information & PoC

## Description
Detected exposed Postman collection JSON files that contained API endpoints and environment details. These files were publicly accessible and disclosed authentication headers and other sensitive information.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/postman.json
GET {{BaseURL}}/docs/postman.json
GET {{BaseURL}}/api/postman.json
GET {{BaseURL}}/postman_collection.json
GET {{BaseURL}}/collections/postman.json
```

## References
- https://medium.com/@utkarshporwal24/exposed-postman-collections-ed6086b96ba5
