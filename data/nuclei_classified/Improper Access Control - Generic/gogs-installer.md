# Nuclei Template: Gogs (Go Git Service) - Installer
**Template ID:** gogs-installer
**Vulnerability Class:** Improper Access Control - Generic
**Severity:** Critical
**CWE:** CWE-284
**Source:** Nuclei Template (`gogs-installer.yaml`)

## Vulnerability Information & PoC

## Description
Go Git Service installer panel was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/install
```

