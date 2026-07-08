# Vulnerability: Listmonk Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`listmonk-installer.yaml`)

## Description
Listmonk is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/login?next=%2Fadmin
```

