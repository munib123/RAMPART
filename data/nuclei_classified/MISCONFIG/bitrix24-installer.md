# Vulnerability: Bitrix24 Installation Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`bitrix24-installer.yaml`)

## Description
Bitrix24 is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

