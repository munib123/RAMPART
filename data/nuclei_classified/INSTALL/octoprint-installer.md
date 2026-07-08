# Vulnerability: OctoPrint Installation Page - Exposure
**Classification:** INSTALL
**Source:** Nuclei Template (`octoprint-installer.yaml`)

## Description
Checks for the presence of a OctoPrint Installer Page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

