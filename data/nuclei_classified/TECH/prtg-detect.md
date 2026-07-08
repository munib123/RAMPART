# Vulnerability: Detect PRTG
**Classification:** TECH
**Source:** Nuclei Template (`prtg-detect.yaml`)

## Description
Monitor all the systems, devices, traffic, and applications in your IT infrastructure -- https://www.paessler.com/prtg

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.htm
GET {{BaseURL}}/prtg/index.htm
GET {{BaseURL}}/PRTG/index.htm
```

