# Vulnerability: Golang Expvar - Detect
**Classification:** GO
**Source:** Nuclei Template (`debug-vars.yaml`)

## Description
Golang expvar function exposes multiple public variables via HTTP such as stack trace information and server operation counters.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/debug/vars
```

