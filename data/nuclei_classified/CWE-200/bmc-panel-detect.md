# Vulnerability: BMC Discovery Outpost Admin Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`bmc-panel-detect.yaml`)

## Description
BMC Discovery Outpost admin panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/adminlogin
```

