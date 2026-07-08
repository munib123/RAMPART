# Vulnerability: Read the Docs Takeover Detection
**Classification:** TAKEOVER
**Source:** Nuclei Template (`readthedocs-takeover.yaml`)

## Description
Read the Docs takeover was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

