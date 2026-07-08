# Vulnerability: HP iLO
**Classification:** TECH
**Source:** Nuclei Template (`ilo-detect.yaml`)

## Description
Version of HP iLO

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/xmldata?item=all
```

