# Vulnerability: Cloud Config File Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`cloud-config.yaml`)

## Description
Cloud Config file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cloud-config.yml
GET {{BaseURL}}/core-cloud-config.yml
GET {{BaseURL}}/cloud-config.txt
```

