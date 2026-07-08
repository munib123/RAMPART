# Vulnerability: Open Journal Systems Installer - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`ojs-installer.yaml`)

## Description
Open Journal Systems is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index/install
GET {{BaseURL}}/index.php/index/install
```

