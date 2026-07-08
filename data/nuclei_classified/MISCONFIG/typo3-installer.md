# Vulnerability: TYPO3 Installer
**Classification:** MISCONFIG
**Source:** Nuclei Template (`typo3-installer.yaml`)

## Description
TYPO3 is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/typo3/install.php
```

