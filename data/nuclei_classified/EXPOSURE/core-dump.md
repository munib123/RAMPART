# Vulnerability: Exposed Core Dump - File Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`core-dump.yaml`)

## Description
Exposed Core Dump internal file is disclosed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/core
```

