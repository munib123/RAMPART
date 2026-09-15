# Nuclei Template: Ventrilo Configuration File - Detect
**Template ID:** ventrilo-config
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`ventrilo-config.yaml`)

## Vulnerability Information & PoC

## Description
Ventrilo configuration file was detected, The file discloses the application's Adminpassword and Password.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/ventrilo_srv.ini
```

## References
- https://www.ventrilo.com/setup.php
