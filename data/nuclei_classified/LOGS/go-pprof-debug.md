# Vulnerability: Go pprof Debug Page
**Classification:** LOGS
**Source:** Nuclei Template (`go-pprof-debug.yaml`)

## Description
go pprof debug page was exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/debug/pprof/heap?debug=1
GET {{BaseURL}}/pprof/heap?debug=1
```

