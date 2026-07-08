# Vulnerability: VMware Workspace ONE UEM Airwatch Self-Service Portal - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`workspace-one-uem-ssp.yaml`)

## Description
VMware Workspace ONE UEM Airwatch Self-Service Portal (SSP) login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/MyDevice/Login
```

