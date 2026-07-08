# Vulnerability: Roundcube Webmail Installer - Exposure
**Classification:** ROUNDCUBE
**Source:** Nuclei Template (`roundcube-installer-exposure.yaml`)

## Description
Detects exposure of the Roundcube Webmail installer interface. Public access to this installer may allow attackers to reconfigure the webmail application, potentially leading to email account compromise or the disclosure of sensitive configuration details.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/installer/
GET {{BaseURL}}/installer/index.php?_step=2
```

