# Vulnerability: apache-axis-detect
**Classification:** TECH
**Source:** Nuclei Template (`apache-axis-detect.yaml`)

## Description
Axis and Axis2 detection

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/axis2/
GET {{BaseURL}}/axis/
```

