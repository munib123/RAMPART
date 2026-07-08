# Vulnerability: FFserver Status Detect
**Classification:** EXPOSURE
**Source:** Nuclei Template (`ffserver-status.yaml`)

## Description
FFserver status panel exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

