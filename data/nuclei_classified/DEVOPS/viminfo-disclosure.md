# Vulnerability: Viminfo - File Disclosure
**Classification:** DEVOPS
**Source:** Nuclei Template (`viminfo-disclosure.yaml`)

## Description
Viminfo file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.viminfo
```

