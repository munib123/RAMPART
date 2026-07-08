# Vulnerability: Detect MRTG
**Classification:** TECH
**Source:** Nuclei Template (`mrtg-detect.yaml`)

## Description
The Multi Router Traffic Grapher

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/mrtg/
GET {{BaseURL}}/MRTG/
```

