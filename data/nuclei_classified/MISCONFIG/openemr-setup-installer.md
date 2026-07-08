# Vulnerability: OpenEMR Setup Installation Page - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`openemr-setup-installer.yaml`)

## Description
Detects exposed OpenEMR setup installation pages which could allow unauthorized access or information disclosure.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/setup.php
```

