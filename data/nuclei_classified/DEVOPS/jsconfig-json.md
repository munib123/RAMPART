# Vulnerability: Visual Studio Code jsconfig.json - Detect
**Classification:** DEVOPS
**Source:** Nuclei Template (`jsconfig-json.yaml`)

## Description
Visual Studio Code jsconfig.json was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/jsconfig.json
```

