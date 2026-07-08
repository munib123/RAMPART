# Vulnerability: elFinder - Install Detection
**Classification:** CWE-200
**Source:** Nuclei Template (`elfinder-detect.yaml`)

## Description
An elFinder implementation was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/elfinder.html
```

