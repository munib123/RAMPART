# Vulnerability: Turbo Website Reviewer Installer Panel
**Classification:** TURBO
**Source:** Nuclei Template (`turbo-website-installer.yaml`)

## Description
Turbo Website Reviewer is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/install/install.php
```

