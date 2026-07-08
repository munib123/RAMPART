# Vulnerability: phpwind Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`phpwind-installer.yaml`)

## Description
phpwind is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install.php?a=check
```

