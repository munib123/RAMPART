# Vulnerability: BMC Discovery Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`bmc-discovery-panel.yaml`)

## Description
BMC Discovery login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ui/
```

