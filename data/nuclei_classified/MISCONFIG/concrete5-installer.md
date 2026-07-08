# Vulnerability: Concrete5 - Installer Page Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`concrete5-installer.yaml`)

## Description
Detects exposed Concrete5 Installation page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php/install
GET {{BaseURL}}/concrete5/index.php/install
```

