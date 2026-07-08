# Vulnerability: AspNetMvc Version - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`aspnetmvc-version-disclosure.yaml`)

## Description
Detects version disclosed via 'X-AspNetMvc-Version' header.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/%3f
```

