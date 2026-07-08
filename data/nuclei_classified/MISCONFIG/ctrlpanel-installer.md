# Vulnerability: CtrlPanel Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`ctrlpanel-installer.yaml`)

## Description
CtrlPanel is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/installer/
```

