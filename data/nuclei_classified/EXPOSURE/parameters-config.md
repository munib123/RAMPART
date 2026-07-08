# Vulnerability: Parameters.yml - File Discovery
**Classification:** EXPOSURE
**Source:** Nuclei Template (`parameters-config.yaml`)

## Description
Parameters.yml was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/parameters.yml
GET {{BaseURL}}/app/config/parameters.yml
GET {{BaseURL}}/parameters.yml.dist
GET {{BaseURL}}/app/config/parameters.yml.dist
```

