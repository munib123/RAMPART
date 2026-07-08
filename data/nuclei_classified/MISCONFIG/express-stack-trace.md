# Vulnerability: Express Stack Trace
**Classification:** MISCONFIG
**Source:** Nuclei Template (`express-stack-trace.yaml`)

## Description
Express Stack trace is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/{{randstr}}
```

