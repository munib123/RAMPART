# Vulnerability: Contentify Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`contentify-installer.yaml`)

## Description
Contentify is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install
```

