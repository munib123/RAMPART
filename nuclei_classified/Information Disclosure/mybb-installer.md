# Nuclei Template: MyBB Installation Panel - Detect
**Template ID:** mybb-installer
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`mybb-installer.yaml`)

## Vulnerability Information & PoC

## Description
Detects exposed MyBB Installation page.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/install/index.php
```

