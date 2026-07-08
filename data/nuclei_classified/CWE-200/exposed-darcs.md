# Vulnerability: Darcs Configuration - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`exposed-darcs.yaml`)

## Description
Darcs configuration was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_darcs/prefs/binaries
```

