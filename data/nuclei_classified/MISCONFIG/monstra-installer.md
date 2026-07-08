# Vulnerability: Monstra Installation Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`monstra-installer.yaml`)

## Description
Monstra is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

