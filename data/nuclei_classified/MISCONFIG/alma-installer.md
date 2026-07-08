# Vulnerability: Alma Installation Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`alma-installer.yaml`)

## Description
Alma is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/setup/start
```

