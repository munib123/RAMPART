# Vulnerability: Detect Telerik Web UI Dialog Handler
**Classification:** TECH
**Source:** Nuclei Template (`telerik-dialoghandler-detect.yaml`)

## Description
This template detects the Telerik Web UI Dialog Handler.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

