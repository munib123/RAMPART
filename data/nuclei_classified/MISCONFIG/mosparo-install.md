# Vulnerability: mosparo Exposed Installation
**Classification:** MISCONFIG
**Source:** Nuclei Template (`mosparo-install.yaml`)

## Description
mosparo is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/setup/
```

