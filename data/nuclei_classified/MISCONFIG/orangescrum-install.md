# Vulnerability: Orangescrum Exposed Installation
**Classification:** MISCONFIG
**Source:** Nuclei Template (`orangescrum-install.yaml`)

## Description
Orangescrum is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

