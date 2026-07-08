# Vulnerability: Badarg Log File Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`badarg-log.yaml`)

## Description
Badarg log file was exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.badarg.log
```

