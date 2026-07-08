# Vulnerability: Ivanti Endpoint Manager (EPM) - Detect
**Classification:** DETECT
**Source:** Nuclei Template (`ivanti-epm-detect.yaml`)

## Description
An Ivanti Endpoint Manager was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/favicon.ico
GET {{BaseURL}}/images/favicon.ico
```

