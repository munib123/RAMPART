# Vulnerability: AriaNg Debug Console - Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`ariang-debug-console.yaml`)

## Description
Detects the presence of AriaNg Debug Console exposure

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

