# Vulnerability: ACEmanager Detection
**Classification:** CWE-200
**Source:** Nuclei Template (`acemanager-login.yaml`)

## Description
ACEManager was detected. ACEManager is a configuration and diagnostic tool for the Sierra Wireless AirLink Raven modems.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

