# Vulnerability: WSO2 Products - Detect
**Classification:** TECH
**Source:** Nuclei Template (`wso2-products-detect.yaml`)

## Description
Try to detect the presence of a WSO2 products instance via the version endpoint

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/services/Version
```

