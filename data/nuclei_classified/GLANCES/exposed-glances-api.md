# Vulnerability: Exposed Glances API
**Classification:** GLANCES
**Source:** Nuclei Template (`exposed-glances-api.yaml`)

## Description
Glances is a cross-platform system monitoring tool written in Python.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

