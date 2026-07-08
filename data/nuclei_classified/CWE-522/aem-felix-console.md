# Vulnerability: Adobe Experience Manager Felix Console - Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`aem-felix-console.yaml`)

## Description
Adobe Experience Manager Felix Console contains a default admin login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations. Remote code execution may also be possible via installation of OSGI bundle.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/system/console/bundles
GET {{BaseURL}}///system///console///bundles
```

