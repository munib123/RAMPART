# Vulnerability: Google Api Private Key
**Classification:** EXPOSURE
**Source:** Nuclei Template (`google-api-private-key.yaml`)

## Description
Google API private keys are exposed in files.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/google-api-private-key.json
GET {{BaseURL}}/app/config/pimcore/google-api-private-key.json
GET {{BaseURL}}/pimcore/app/config/pimcore/google-api-private-key.json
```

