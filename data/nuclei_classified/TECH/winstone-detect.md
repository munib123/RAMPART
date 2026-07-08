# Vulnerability: Winstone Servlet Engine
**Classification:** TECH
**Source:** Nuclei Template (`winstone-detect.yaml`)

## Description
Detected servers running the Winstone Servlet Engine via the Server or X-Powered-By headers.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

