# Vulnerability: AsyncAPI Spec Inventory
**Classification:** EXPOSURE
**Source:** Nuclei Template (`asyncapi-inventory.yaml`)

## Description
Detected publicly accessible AsyncAPI specification files (YAML/JSON), which might have exposed message channels, server endpoints, and security schemes.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/asyncapi
GET {{BaseURL}}/asyncapi.yaml
GET {{BaseURL}}/asyncapi.yml
GET {{BaseURL}}/asyncapi.json
GET {{BaseURL}}/api/asyncapi
GET {{BaseURL}}/api/docs/asyncapi
GET {{BaseURL}}/docs/asyncapi
```

