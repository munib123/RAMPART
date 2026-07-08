# Vulnerability: Publicly accessible NPM Log file
**Classification:** NPM
**Source:** Nuclei Template (`npm-log-file.yaml`)

## Description
NPM log file is exposed to external users.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/npm-debug.log
GET {{BaseURL}}/assets/npm-debug.log
```

