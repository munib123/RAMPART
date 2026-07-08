# Vulnerability: Vugex Framework Source Code - Detect
**Classification:** VUGEX
**Source:** Nuclei Template (`vugex-source-detect.yaml`)

## Description
Detects the presence of exposed Vugex Framework source code by identifying common files and directories associated with the framework.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
```

