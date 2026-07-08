# Vulnerability: Eslint Ignore File Exposure
**Classification:** ESLINTIGNORE
**Source:** Nuclei Template (`eslint-ignore-exposure.yaml`)

## Description
Eslint Ignore File was exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.eslintignore
```

