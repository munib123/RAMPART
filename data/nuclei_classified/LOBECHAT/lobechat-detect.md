# Vulnerability: LobeChat - Detect
**Classification:** LOBECHAT
**Source:** Nuclei Template (`lobechat-detect.yaml`)

## Description
An instance running LobeChat was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/welcome
```

