# Nuclei Template: Adobe Experience Manager Felix Console - Default Login
**Template ID:** aem-felix-console
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`aem-felix-console.yaml`)

## Vulnerability Information & PoC

## Description
Adobe Experience Manager Felix Console contains a default admin login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations. Remote code execution may also be possible via installation of OSGI bundle.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/system/console/bundles
GET {{BaseURL}}///system///console///bundles
```

## References
- https://github.com/0ang3el/aem-hacker/blob/master/aem_hacker.py
- https://github.com/0ang3el/aem-rce-bundle
