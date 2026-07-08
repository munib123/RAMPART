# Vulnerability: Exposed Browserless debugger
**Classification:** BROWSERLESS
**Source:** Nuclei Template (`browserless-debugger.yaml`)

## Description
Browserless instance can be used to make web requests. May worth checking /workspace for juicy files.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

