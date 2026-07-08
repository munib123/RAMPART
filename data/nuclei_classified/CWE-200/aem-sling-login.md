# Vulnerability: Adobe Experience Manager Sling User Login - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`aem-sling-login.yaml`)

## Description
Adobe Experience Manager Sling user login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/system/sling/cqform/defaultlogin.html
```

