# Vulnerability: Hugo Detect
**Classification:** TECH
**Source:** Nuclei Template (`hugo-detect.yaml`)

## Description
Hugo is a fast and modern static site generator written in Go

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

