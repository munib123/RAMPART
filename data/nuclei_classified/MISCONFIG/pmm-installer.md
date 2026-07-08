# Vulnerability: PMM Installation Wizard
**Classification:** MISCONFIG
**Source:** Nuclei Template (`pmm-installer.yaml`)

## Description
PMM is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/password-page/ovf/account-credentials-ovf
```

