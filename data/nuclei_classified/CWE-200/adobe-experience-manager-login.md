# Vulnerability: Adobe Experience Manager Login Panel
**Classification:** CWE-200
**Source:** Nuclei Template (`adobe-experience-manager-login.yaml`)

## Description
An Adobe Experience Manager login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/libs/granite/core/content/login.html
```

