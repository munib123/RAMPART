# Vulnerability: VMware Workspace ONE UEM Airwatch Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`workspace-one-uem.yaml`)

## Description
VMware Workspace ONE UEM Airwatch login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/AirWatch/Login
```

