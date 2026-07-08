# Vulnerability: MantisBT Installation Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`mantisbt-installer.yaml`)

## Description
MantisBT is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/install.php
```

