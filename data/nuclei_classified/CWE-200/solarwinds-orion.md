# Vulnerability: SolarWinds Orion Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`solarwinds-orion.yaml`)

## Description
SolarWinds Orion login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Orion/Login.aspx
```

