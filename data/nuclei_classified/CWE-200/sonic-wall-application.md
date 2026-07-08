# Vulnerability: SonicWall Appliance Management Console Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sonic-wall-application.yaml`)

## Description
SonicWall Appliance Management Console login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.do
```

