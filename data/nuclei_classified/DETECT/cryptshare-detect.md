# Vulnerability: Pointsharp Cryptshare - Detect
**Classification:** DETECT
**Source:** Nuclei Template (`cryptshare-detect.yaml`)

## Description
Detects the presence of Pointsharp Cryptshare secure email and file sharing server.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Start?0
```

