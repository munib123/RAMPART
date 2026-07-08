# Vulnerability: Detect Darkstat Reports
**Classification:** DARKSTAT
**Source:** Nuclei Template (`darkstat-detect.yaml`)

## Description
Darkstat captures network traffic, calculates statistics about usage, and serves reports over HTTP

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/darkstat/
```

