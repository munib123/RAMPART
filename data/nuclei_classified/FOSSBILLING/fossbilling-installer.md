# Vulnerability: FOSSBilling - Installation
**Classification:** FOSSBILLING
**Source:** Nuclei Template (`fossbilling-installer.yaml`)

## Description
FOSSBilling installation dashboard has been detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/install.php
```

