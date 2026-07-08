# Vulnerability: SyncThru Web Service Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`syncthru-web-service.yaml`)

## Description
SyncThru Web Service panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/sws/index.sws
```

