# Nuclei Template: CirCarLife - Installer
**Template ID:** circarlife-installer
**Vulnerability Class:** Improper Access Control - Generic
**Severity:** Critical
**CWE:** CWE-284
**Source:** Nuclei Template (`circarlife-setup.yaml`)

## Vulnerability Information & PoC

## Description
A CirCarLife admin panel was accessed. CirCarLife is an internet-connected electric vehicle charging station

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/html/setup.html
```

## References
- https://circontrol.com/
