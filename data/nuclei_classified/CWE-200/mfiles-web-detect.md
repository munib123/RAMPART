# Vulnerability: M-Files Web Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mfiles-web-detect.yaml`)

## Description
M-Files Web login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/Login.aspx
```

