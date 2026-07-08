# Vulnerability: QuickCMS Installation Wizard
**Classification:** MISCONFIG
**Source:** Nuclei Template (`quickcms-installer.yaml`)

## Description
PMM is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/
```

