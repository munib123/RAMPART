# Vulnerability: UniFi Wizard Installer
**Classification:** MISCONFIG
**Source:** Nuclei Template (`unifi-wizard-install.yaml`)

## Description
UniFi Wizard is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/manage/wizard/
```

