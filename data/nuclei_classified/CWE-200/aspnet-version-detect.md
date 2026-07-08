# Vulnerability: AspNet Version Disclosure - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`aspnet-version-detect.yaml`)

## Description
Detects version disclosed via 'X-AspNet-Version' header.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/%3f
```

