# Vulnerability: WebTrees Exposed Installation
**Classification:** MISCONFIG
**Source:** Nuclei Template (`webtrees-install.yaml`)

## Description
WebTrees is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

