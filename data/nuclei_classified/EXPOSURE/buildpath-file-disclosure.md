# Vulnerability: .buildpath - File Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`buildpath-file-disclosure.yaml`)

## Description
Publicly accessible /.buildpath configuration file was detected, which may expose project structure or sensitive information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.buildpath
```

