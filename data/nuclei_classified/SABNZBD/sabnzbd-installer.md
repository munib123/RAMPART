# Vulnerability: SABnzbd Quick-Start Wizard - Exposure
**Classification:** SABNZBD
**Source:** Nuclei Template (`sabnzbd-installer.yaml`)

## Description
Default installation wizard page of SABnzbd was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/sabnzbd/wizard/
GET {{BaseURL}}/wizard/
```

