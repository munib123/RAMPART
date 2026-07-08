# Vulnerability: Umbraco Install - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`umbraco-installer.yaml`)

## Description
Umbraco is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install
GET {{BaseURL}}/umbraco/management/api/v1/server/status
```

