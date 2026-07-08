# Vulnerability: Confluence Installation Page - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`confluence-installer.yaml`)

## Description
Confluence is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/setup/setupcluster-start.action
```

