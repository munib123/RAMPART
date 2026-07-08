# Vulnerability: Easy Installer by ViserLab - Exposure
**Classification:** INSTALL
**Source:** Nuclei Template (`easy-viserlabs-installer.yaml`)

## Description
Checks for the presence of a Easy Installer by ViserLab.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/
```

