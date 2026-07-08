# Vulnerability: OSQuery Fleet Detection Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`osquery-fleet-detect.yaml`)

## Description
OSQuery Fleet Detection panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

