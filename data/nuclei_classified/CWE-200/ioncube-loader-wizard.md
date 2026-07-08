# Vulnerability: ioncube Loader Wizard Disclosure
**Classification:** CWE-200
**Source:** Nuclei Template (`ioncube-loader-wizard.yaml`)

## Description
An ioncube Loader Wizard was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ioncube/loader-wizard.php
GET {{BaseURL}}/loader-wizard.php
```

