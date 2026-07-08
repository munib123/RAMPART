# Vulnerability: Adobe AEM Security Users Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`aem-security-users.yaml`)

## Description
Adobe AEM Security Users are exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/libs/granite/security/content/useradmin.html
```

