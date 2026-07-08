# Vulnerability: Common Error Log Files
**Classification:** LOGS
**Source:** Nuclei Template (`error-logs.yaml`)

## Description
Error log files were exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

