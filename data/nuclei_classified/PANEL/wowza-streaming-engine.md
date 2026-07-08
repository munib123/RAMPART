# Vulnerability: Wowza Streaming Engine Manager Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`wowza-streaming-engine.yaml`)

## Description
Wowza Streaming Engine Manager panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/enginemanager/ftu/welcome.htm
```

