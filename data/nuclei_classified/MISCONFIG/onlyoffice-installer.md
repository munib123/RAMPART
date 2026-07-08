# Vulnerability: OnlyOffice Wizard Page - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`onlyoffice-installer.yaml`)

## Description
Detects exposed OnlyOffice Setup page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Wizard.aspx
```

