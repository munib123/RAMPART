# Vulnerability: Pritunl - Installation
**Classification:** PRITUNL
**Source:** Nuclei Template (`pritunl-installer.yaml`)

## Description
Pritunl is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/setup
```

