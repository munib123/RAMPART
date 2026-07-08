# Vulnerability: Cleo Technology - Detect
**Classification:** TECH
**Source:** Nuclei Template (`cleo-detect.yaml`)

## Description
This template detects Cleo technologies, including VLTrader, Harmony, and LexiCom, by inspecting response headers.It also extracts version information for each identified technology.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

