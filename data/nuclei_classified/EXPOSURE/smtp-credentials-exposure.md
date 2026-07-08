# Vulnerability: SMTP Credentials Exposure - Detection
**Classification:** EXPOSURE
**Source:** Nuclei Template (`smtp-credentials-exposure.yaml`)

## Description
Detects exposed SMTP credentials (username and password) in a webpage's HTML or JavaScript source code.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

