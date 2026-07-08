# Vulnerability: LMSZAI Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`lmszai-installer.yaml`)

## Description
LMSZAI is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install
```

