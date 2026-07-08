# Vulnerability: ASP.NET Trace.AXD - Exposure
**Classification:** LOGS
**Source:** Nuclei Template (`trace-axd-expose.yaml`)

## Description
ASP.NET Trace.AXD information was exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Trace.axd
```

