# Vulnerability: ChurchCRM - Setup Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`churchcrm-installer.yaml`)

## Description
ChurchCRM setup is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/setup
```

