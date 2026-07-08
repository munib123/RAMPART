# Vulnerability: IBM API Connect Developer Portal - Detect
**Classification:** TECH
**Source:** Nuclei Template (`ibm-api-connect-developer-portal-detect.yaml`)

## Description
IBM API Connect Developer Portal was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/favicon.ico
GET {{BaseURL}}/modules/ibm_apim/ibm_apim.info.yml
```

