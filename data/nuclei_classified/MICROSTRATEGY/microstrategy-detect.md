# Vulnerability: MicroStrategy Instances Detection Template
**Classification:** MICROSTRATEGY
**Source:** Nuclei Template (`microstrategy-detect.yaml`)

## Description
Detect if MicroStrategy instances exist in your URLS

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/{{path}}
```

