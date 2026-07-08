# Vulnerability: Ivanti Endpoint Manager - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ivanti-endpoint-manager.yaml`)

## Description
Detects the presence of Ivanti Endpoint Manager (formerly LANDesk Management Suite) servers.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/ldlogon.dll
GET {{BaseURL}}/core/login
GET {{BaseURL}}/webaccess
```

