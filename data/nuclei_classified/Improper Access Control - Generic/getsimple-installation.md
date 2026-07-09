# Nuclei Template: GetSimple CMS - Installer
**Template ID:** getsimple-installation
**Vulnerability Class:** Improper Access Control - Generic
**Severity:** Critical
**CWE:** CWE-284
**Source:** Nuclei Template (`getsimple-installation.yaml`)

## Vulnerability Information & PoC

## Description
GetSimple CMS installer was found.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/admin/install.php
```

## References
- http://get-simple.info/
