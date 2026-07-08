# Vulnerability: Binom Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`binom-installer.yaml`)

## Description
Binom is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
GET {{BaseURL}}/?page=step_1
```

