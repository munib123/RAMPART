# Vulnerability: Weaviate - Exposure
**Classification:** WEAVIATE
**Source:** Nuclei Template (`weaviate-exposure.yaml`)

## Description
Detected an exposed Weaviate instance by accessing its API endpoints. Verified exposure by identifying meta information, schema details, and specific endpoint references in the response, confirming that the instance was publicly accessible.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/v1/
```

