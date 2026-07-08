# Vulnerability: Piwik Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`piwik-installer.yaml`)

## Description
Piwik is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

