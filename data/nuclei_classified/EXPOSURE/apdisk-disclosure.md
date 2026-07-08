# Vulnerability: Apdisk - File Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`apdisk-disclosure.yaml`)

## Description
Apdisk internal file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.apdisk
```

