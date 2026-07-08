# Vulnerability: OpenMage Installation Wizard
**Classification:** MISCONFIG
**Source:** Nuclei Template (`openmage-install.yaml`)

## Description
OpenMage is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php/install/
```

