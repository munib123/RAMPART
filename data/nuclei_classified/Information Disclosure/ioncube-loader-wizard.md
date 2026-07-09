# Nuclei Template: ioncube Loader Wizard Disclosure
**Template ID:** ioncube-loader-wizard
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`ioncube-loader-wizard.yaml`)

## Vulnerability Information & PoC

## Description
An ioncube Loader Wizard was discovered.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/ioncube/loader-wizard.php
GET {{BaseURL}}/loader-wizard.php
```

## References
- https://firefart.at/post/multiple-vulnerabilities-in-ioncube-loader-wizard/
