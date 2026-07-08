# Vulnerability: Ruckus Unleashed Exposed Installation
**Classification:** MISCONFIG
**Source:** Nuclei Template (`ruckus-unleashed-install.yaml`)

## Description
Ruckus Unleashed is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/wizard.jsp
```

